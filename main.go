package main

import (

	// TUSD and DataStore
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/tus/tusd/pkg/filestore"
	tusd "github.com/tus/tusd/pkg/handler"

	// Adapter for net/http
	"github.com/gofiber/adaptor"
	// Fiber
	"github.com/gofiber/fiber"
	// CORS
	"github.com/gofiber/cors"
	// "github.com/rs/cors"
)

// HTTPError represents an error with an additional status code attached
// which may be used when this error is sent in a HTTP response.
// See the net/http package for standardized status codes.
type HTTPError interface {
	error
	StatusCode() int
	Body() []byte
}

var (
	reExtractFileID  = regexp.MustCompile(`([^/]+)\/?$`)
	reForwardedHost  = regexp.MustCompile(`host=([^,]+)`)
	reForwardedProto = regexp.MustCompile(`proto=(https?)`)
	reMimeType       = regexp.MustCompile(`^[a-z]+\/[a-z0-9\-\+\.]+$`)
)

// NewHTTPError adds the given status code to the provided error and returns
// the new error instance. The status code may be used in corresponding HTTP
// responses. See the net/http package for standardized status codes.
func NewHTTPError(err error, statusCode int) HTTPError {
	return httpError{err, statusCode}
}

var (
	ErrUnsupportedVersion               = NewHTTPError(errors.New("unsupported version"), http.StatusPreconditionFailed)
	ErrMaxSizeExceeded                  = NewHTTPError(errors.New("maximum size exceeded"), http.StatusRequestEntityTooLarge)
	ErrInvalidContentType               = NewHTTPError(errors.New("missing or invalid Content-Type header"), http.StatusBadRequest)
	ErrInvalidUploadLength              = NewHTTPError(errors.New("missing or invalid Upload-Length header"), http.StatusBadRequest)
	ErrInvalidOffset                    = NewHTTPError(errors.New("missing or invalid Upload-Offset header"), http.StatusBadRequest)
	ErrNotFound                         = NewHTTPError(errors.New("upload not found"), http.StatusNotFound)
	ErrFileLocked                       = NewHTTPError(errors.New("file currently locked"), 423) // Locked (WebDAV) (RFC 4918)
	ErrMismatchOffset                   = NewHTTPError(errors.New("mismatched offset"), http.StatusConflict)
	ErrSizeExceeded                     = NewHTTPError(errors.New("resource's size exceeded"), http.StatusRequestEntityTooLarge)
	ErrNotImplemented                   = NewHTTPError(errors.New("feature not implemented"), http.StatusNotImplemented)
	ErrUploadNotFinished                = NewHTTPError(errors.New("one of the partial uploads is not finished"), http.StatusBadRequest)
	ErrInvalidConcat                    = NewHTTPError(errors.New("invalid Upload-Concat header"), http.StatusBadRequest)
	ErrModifyFinal                      = NewHTTPError(errors.New("modifying a final upload is not allowed"), http.StatusForbidden)
	ErrUploadLengthAndUploadDeferLength = NewHTTPError(errors.New("provided both Upload-Length and Upload-Defer-Length"), http.StatusBadRequest)
	ErrInvalidUploadDeferLength         = NewHTTPError(errors.New("invalid Upload-Defer-Length header"), http.StatusBadRequest)
	ErrUploadStoppedByServer            = NewHTTPError(errors.New("upload has been stopped by server"), http.StatusBadRequest)
)

// extractIDFromPath pulls the last segment from the url provided
func extractIDFromPath(url string) (string, error) {
	result := reExtractFileID.FindStringSubmatch(url)
	if len(result) != 2 {
		return "", ErrNotFound
	}
	return result[1], nil
}

func i64toa(num int64) string {
	return strconv.FormatInt(num, 10)
}

// Parse the Upload-Concat header, e.g.
// Upload-Concat: partial
// Upload-Concat: final;http://tus.io/files/a /files/b/
func parseConcat(header string) (isPartial bool, isFinal bool, partialUploads []string, err error) {
	if len(header) == 0 {
		return
	}

	if header == "partial" {
		isPartial = true
		return
	}

	l := len("final;")
	if strings.HasPrefix(header, "final;") && len(header) > l {
		isFinal = true

		list := strings.Split(header[l:], " ")
		for _, value := range list {
			value := strings.TrimSpace(value)
			if value == "" {
				continue
			}

			id, extractErr := extractIDFromPath(value)
			if extractErr != nil {
				err = extractErr
				return
			}

			partialUploads = append(partialUploads, id)
		}
	}

	// If no valid partial upload ids are extracted this is not a final upload.
	if len(partialUploads) == 0 {
		isFinal = false
		err = ErrInvalidConcat
	}

	return
}

func main() {
	// Create a new FileStore instance which is responsible for
	// storing the uploaded file on disk in the specified directory.
	// This path _must_ exist before tusd will store uploads in it.
	// If you want to save them on a different medium, for example
	// a remote FTP server, you can implement your own storage backend
	// by implementing the tusd.DataStore interface.
	store := filestore.FileStore{
		Path: "./uploads",
	}

	// A storage backend for tusd may consist of multiple different parts which
	// handle upload creation, locking, termination and so on. The composer is a
	// place where all those separated pieces are joined together. In this example
	// we only use the file store but you may plug in multiple.
	composer := tusd.NewStoreComposer()
	store.UseIn(composer)

	app := fiber.New()

	handler, err := tusd.NewUnroutedHandler(tusd.Config{
		BasePath:              "/files/",
		StoreComposer:         composer,
		NotifyCompleteUploads: true,
	})
	if err != nil {
		panic(fmt.Errorf("Unable to create handler: %s", err))
	}

	go func() {
		for {
			event := <-handler.CompleteUploads
			fmt.Printf("Upload %s finished\n", event.Upload.ID)
		}
	}()

	// CORS
	app.Use(cors.New())
	// TUS Middleware
	// Match any route
	app.Use(func(c *fiber.Ctx) {
		c.Set("Tus-Resumable", "1.0.0")
		c.Next()
	})

	// app.Post("/files", adaptor.HTTPHandlerFunc(handler.PostFile))
	app.Post("/files", func(c *fiber.Ctx) {
		ctx := context.Background()

		// Check for presence of application/offset+octet-stream. If another content
		// type is defined, it will be ignored and treated as none was set because
		// some HTTP clients may enforce a default value for this header.
		containsChunk := c.Get("Content-Type") == "application/offset+octet-stream"

		// Only use the proper Upload-Concat header if the concatenation extension
		// is even supported by the data store.
		var concatHeader string
		if composer.UsesConcater {
			concatHeader = c.Get("Upload-Concat")
		}

		// Parse Upload-Concat header
		isPartial, isFinal, partialUploadIDs, err := parseConcat(concatHeader)
		if err != nil {
			handler.sendError(w, r, err)
			return
		}

		// If the upload is a final upload created by concatenation multiple partial
		// uploads the size is sum of all sizes of these files (no need for
		// Upload-Length header)
		var size int64
		var sizeIsDeferred bool
		var partialUploads []Upload
		if isFinal {
			// A final upload must not contain a chunk within the creation request
			if containsChunk {
				handler.sendError(w, r, ErrModifyFinal)
				return
			}

			partialUploads, size, err = handler.sizeOfUploads(ctx, partialUploadIDs)
			if err != nil {
				handler.sendError(w, r, err)
				return
			}
		} else {
			uploadLengthHeader := r.Header.Get("Upload-Length")
			uploadDeferLengthHeader := r.Header.Get("Upload-Defer-Length")
			size, sizeIsDeferred, err = handler.validateNewUploadLengthHeaders(uploadLengthHeader, uploadDeferLengthHeader)
			if err != nil {
				handler.sendError(w, r, err)
				return
			}
		}

		// Test whether the size is still allowed
		if handler.config.MaxSize > 0 && size > handler.config.MaxSize {
			handler.sendError(w, r, ErrMaxSizeExceeded)
			return
		}

		// Parse metadata
		meta := ParseMetadataHeader(r.Header.Get("Upload-Metadata"))

		info := FileInfo{
			Size:           size,
			SizeIsDeferred: sizeIsDeferred,
			MetaData:       meta,
			IsPartial:      isPartial,
			IsFinal:        isFinal,
			PartialUploads: partialUploadIDs,
		}

		if handler.config.PreUploadCreateCallback != nil {
			if err := handler.config.PreUploadCreateCallback(newHookEvent(info, r)); err != nil {
				handler.sendError(w, r, err)
				return
			}
		}

		upload, err := handler.composer.Core.NewUpload(ctx, info)
		if err != nil {
			handler.sendError(w, r, err)
			return
		}

		info, err = upload.GetInfo(ctx)
		if err != nil {
			handler.sendError(w, r, err)
			return
		}

		id := info.ID

		// Add the Location header directly after creating the new resource to even
		// include it in cases of failure when an error is returned
		url := handler.absFileURL(r, id)
		w.Header().Set("Location", url)

		handler.Metrics.incUploadsCreated()
		handler.log("UploadCreated", "id", id, "size", i64toa(size), "url", url)

		if handler.config.NotifyCreatedUploads {
			handler.CreatedUploads <- newHookEvent(info, r)
		}

		if isFinal {
			concatableUpload := handler.composer.Concater.AsConcatableUpload(upload)
			if err := concatableUpload.ConcatUploads(ctx, partialUploads); err != nil {
				handler.sendError(w, r, err)
				return
			}
			info.Offset = size

			if handler.config.NotifyCompleteUploads {
				handler.CompleteUploads <- newHookEvent(info, r)
			}
		}

		if containsChunk {
			if handler.composer.UsesLocker {
				lock, err := handler.lockUpload(id)
				if err != nil {
					handler.sendError(w, r, err)
					return
				}

				defer lock.Unlock()
			}

			if err := handler.writeChunk(ctx, upload, info, w, r); err != nil {
				handler.sendError(w, r, err)
				return
			}
		} else if !sizeIsDeferred && size == 0 {
			// Directly finish the upload if the upload is empty (i.e. has a size of 0).
			// This statement is in an else-if block to avoid causing duplicate calls
			// to finishUploadIfComplete if an upload is empty and contains a chunk.
			if err := handler.finishUploadIfComplete(ctx, upload, info, r); err != nil {
				handler.sendError(w, r, err)
				return
			}
		}

		handler.sendResp(w, r, http.StatusCreated)
	})
	app.Head("/files/:id", adaptor.HTTPHandlerFunc(handler.HeadFile))
	app.Patch("/files/:id", adaptor.HTTPHandlerFunc(handler.PatchFile))
	app.Get("/files/:id", adaptor.HTTPHandlerFunc(handler.GetFile))
	// app.Delete("/files/:id", adaptor.HTTPHandlerFunc(handler.DelFile))

	// Listen on port 8083
	app.Listen(8083)

	// Create a new HTTP handler for the tusd server by providing a configuration.
	// The StoreComposer property must be set to allow the handler to function.
	/*
		mux, err := tusd.NewHandler(tusd.Config{
			BasePath:              "/files/",
			StoreComposer:         composer,
			NotifyCompleteUploads: true,
		})
		if err != nil {
			panic(fmt.Errorf("Unable to create handler: %s", err))
		}

			// Start another goroutine for receiving events from the handler whenever
			// an upload is completed. The event will contains details about the upload
			// itself and the relevant HTTP request.
			go func() {
				for {
					event := <-mux.CompleteUploads
					fmt.Printf("Upload %s finished\n", event.Upload.ID)
				}
			}()

			// Right now, nothing has happened since we need to start the HTTP server on
			// our own. In the end, tusd will start listening on and accept request at
			// http://localhost:8080/files
			c := cors.New(cors.Options{
				AllowedOrigins:   []string{"*"},
				AllowCredentials: false,
				AllowedHeaders:   []string{"*"},
				AllowedMethods:   []string{"GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"},
				// Enable Debugging for testing, consider disabling in production
				// Debug: true,
			})
			handler := c.Handler(mux)
			// http.Handle("/files/", http.StripPrefix("/files/", handler))
			err = http.ListenAndServe(":8083", http.StripPrefix("/files/", handler))
			if err != nil {
				panic(fmt.Errorf("Unable to listen: %s", err))
			}
	*/
}

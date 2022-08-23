package _115

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rclone/rclone/backend/115/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
)

const (
	userAgent = "Mozilla/5.0 115Browser/23.9.3"
)

var (
	errorReadOnly = errors.New("http remotes are read only")
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "115",
		Description: "115 drive",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "uid",
			Help:     "UID from cookie",
			Required: true,
		}, {
			Name:     "cid",
			Help:     "CID from cookie",
			Required: true,
		}, {
			Name:     "seid",
			Help:     "SEID from cookie",
			Required: true,
		}},
	})
}

// Options defines the configguration of this backend
type Options struct {
	UID  string `config:"uid"`
	CID  string `config:"cid"`
	SEID string `config:"seid"`
}

// Fs represents a remote 115 drive
type Fs struct {
	name     string
	root     string
	opt      Options
	ci       *fs.ConfigInfo
	features *fs.Features
	srv      *rest.Client
	pacer    *fs.Pacer
	cache    *cache.Cache
}

// Object describes a 115 object
type Object struct {
	fs       *Fs
	remote   string
	name     string
	size     int64
	sha1sum  string
	pickCode string
	modTime  time.Time
}

// shouldRetry returns a boolean as to whether this resp and err
// deserve to be retried.  It returns the err as a convenience
func shouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// TODO: impl
	return false, err
}

// ------------------------------------------------------------

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name string, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	ci := fs.GetConfig(ctx)
	f := &Fs{
		name:  name,
		root:  root,
		opt:   *opt,
		ci:    ci,
		srv:   rest.NewClient(&http.Client{}),
		pacer: fs.NewPacer(ctx, pacer.NewDefault()),
		cache: cache.New(time.Minute*2, time.Minute*4),
	}
	f.srv.SetHeader("User-Agent", userAgent)
	f.srv.SetCookie(&http.Cookie{
		Name:     "UID",
		Value:    opt.UID,
		Domain:   "www.115.com",
		Path:     "/",
		HttpOnly: true,
	}, &http.Cookie{
		Name:     "CID",
		Value:    opt.CID,
		Domain:   "www.115.com",
		Path:     "/",
		HttpOnly: true,
	}, &http.Cookie{
		Name:     "SEID",
		Value:    opt.SEID,
		Domain:   "www.115.com",
		Path:     "/",
		HttpOnly: true,
	})
	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	// TODO: login check

	return f, nil
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to string
func (f *Fs) String() string {
	return fmt.Sprintf("115 %s", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Precision return the precision of this Fs
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Hashes returns the supported hash sets.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.SHA1)
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
// TODO: impl
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return nil, nil
}

// List the objects and directories in dir into entries
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	dir = f.slashClean(dir)
	cacheKey := fmt.Sprintf("files:%s", dir)
	if value, ok := f.cache.Get(cacheKey); ok {
		return value.([]fs.DirEntry), nil
	}

	cid, err := f.getDirID(ctx, dir)
	if err != nil {
		return nil, err
	}

	pageSize := int64(1000)
	offset := int64(0)
	files := make([]fs.DirEntry, 0)
	for {
		resp, err := f.getFiles(ctx, cid, pageSize, offset)
		if err != nil {
			return nil, err
		}

		for _, fi := range resp.Data {
			remote := path.Join(dir, fi.GetName())
			item, err := f.itemToDirEntry(ctx, remote, &fi)
			if err != nil {
				return nil, err
			}
			files = append(files, item)
		}

		offset = resp.Offset + pageSize
		if offset >= resp.Count {
			break
		}
	}
	f.cache.SetDefault(cacheKey, files)

	return files, nil
}

// Put in to the remote path with the modTime given of the given size
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return nil, errorReadOnly
}

// PutStream uploads to the remote path with the modTime given of indeterminate size
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return nil, errorReadOnly
}

// CreateDir makes a directory
// TODO: impl
func (f *Fs) CreateDir(ctx context.Context, path string) (err error) {
	return nil
}

// Mkdir creates the container if it doesn't exist
// TODO: impl
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return nil
}

// Rmdir deletes the container
// TODO: impl
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return nil
}

func (f *Fs) itemToDirEntry(ctx context.Context, remote string, object *api.FileInfo) (fs.DirEntry, error) {
	if len(remote) > 0 && remote[0] == '/' {
		remote = remote[1:]
	}
	if object.IsDir() {
		t := object.GetUpdateTime()
		d := fs.NewDir(remote, t).SetSize(object.GetSize())
		return d, nil
	} else {
		o, err := f.newObjectWithInfo(ctx, remote, object)
		if err != nil {
			return nil, err
		}
		return o, nil
	}
}

// TODO: impl
func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, object *api.FileInfo) (fs.DirEntry, error) {
	o := &Object{
		fs:       f,
		remote:   remote,
		name:     object.GetName(),
		size:     object.GetSize(),
		sha1sum:  object.Sha1,
		pickCode: object.PickCode,
	}
	return o, nil
}

func (f *Fs) getDirID(ctx context.Context, dir string) (string, error) {
	opts := rest.Opts{
		Method:     http.MethodGet,
		RootURL:    "https://webapi.115.com",
		Path:       "/files/getid",
		Parameters: url.Values{},
	}
	opts.Parameters.Set("path", dir)

	var err error
	var info api.GetDirIDResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &info)
		return shouldRetry(ctx, resp, err)
	})

	if err != nil {
		return "", err
	}

	return info.CategoryID.String(), nil
}

func (f *Fs) getFiles(ctx context.Context, cid string, pageSize int64, offset int64) (*api.GetFilesResponse, error) {
	opts := rest.Opts{
		Method:     http.MethodGet,
		RootURL:    "https://webapi.115.com",
		Path:       "/files",
		Parameters: url.Values{},
	}
	opts.Parameters.Set("aid", "1")
	opts.Parameters.Set("cid", cid)
	opts.Parameters.Set("o", "user_ptime")
	opts.Parameters.Set("asc", "0")
	opts.Parameters.Set("offset", strconv.FormatInt(offset, 10))
	opts.Parameters.Set("show_dir", "1")
	opts.Parameters.Set("limit", strconv.FormatInt(pageSize, 10))
	opts.Parameters.Set("snap", "0")
	opts.Parameters.Set("record_open_time", "1")
	opts.Parameters.Set("format", "json")
	opts.Parameters.Set("fc_mix", "0")

	var err error
	var info api.GetFilesResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &info)
		return shouldRetry(ctx, resp, err)
	})

	if err != nil {
		return nil, err
	}

	return &info, nil
}

func (f *Fs) getURL(ctx context.Context, pickCode string) (string, error) {
	key := GenerateKey()
	data, _ := json.Marshal(map[string]string{
		"pickcode": pickCode,
	})

	opts := rest.Opts{
		Method:          http.MethodPost,
		RootURL:         "https://proapi.115.com",
		Path:            "/app/chrome/downurl",
		Parameters:      url.Values{},
		MultipartParams: url.Values{},
	}
	opts.Parameters.Add("t", strconv.FormatInt(time.Now().Unix(), 10))
	opts.MultipartParams.Set("data", Encode(data, key))
	var err error
	var info api.BaseResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &info)
		return shouldRetry(ctx, resp, err)
	})

	if err != nil {
		return "", err
	}

	var respData string
	if err := json.Unmarshal(info.Data, &respData); err != nil {
		return "", fmt.Errorf("api get download url, call json.Unmarshal fail, body: %s", string(info.Data))
	}

	data2, err := Decode(respData, key)
	if err != nil {
		return "", fmt.Errorf("api get download url, call Decode fail, err: %w", err)
	}
	result := api.DownloadData{}
	if err := json.Unmarshal(data2, &result); err != nil {
		return "", fmt.Errorf("api get download url, call json.Unmarshal fail, body: %s", string(data2))
	}

	for _, info := range result {
		fileSize, _ := info.FileSize.Int64()
		if fileSize == 0 {
			return "", fs.ErrorObjectNotFound
		}
		return info.URL.URL, nil
	}

	return "", fs.ErrorObjectNotFound
}

func (f *Fs) slashClean(name string) string {
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	return path.Clean(name)
}

// ------------------------------------------------------------

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs

}

// String convert this Object to string
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// ModTime returns the modification time of the object
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	return o.size
}

// Hash returns the Md5sum of an object returning a lowercase hex string
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	if t != hash.SHA1 {
		return "", hash.ErrUnsupported
	}
	return o.sha1sum, nil
}

// Open an object for read
// TODO: impl
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	targetURL, err := o.fs.getURL(ctx, o.pickCode)
	if err != nil {
		return nil, err
	}

	opts := rest.Opts{
		Method:  http.MethodGet,
		RootURL: targetURL,
		Options: options,
	}

	var resp *http.Response
	err = o.fs.pacer.Call(func() (bool, error) {
		resp, err = o.fs.srv.Call(ctx, &opts)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}

	return resp.Body, err
}

// Remove an object
func (o *Object) Remove(ctx context.Context) error {
	return errorReadOnly
}

// MimeType of an Object if known, "" otherwise
// TODO: impl
func (o *Object) MimeType(ctx context.Context) string {
	return ""
}

// SetModTime sets the modification time of the local fs object
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return errorReadOnly
}

// Storable returns whether this object is storable
func (o *Object) Storable() bool {
	return true
}

// Update in to the object with the modTime given of the given size
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	return errorReadOnly
}

// Check the interfaces are satisfied
var (
	_ fs.Fs = (*Fs)(nil)
	// _ fs.Purger = (*Fs)(nil)
	// _ fs.Copier       = (*Fs)(nil)
	// _ fs.Mover        = (*Fs)(nil)
	// _ fs.DirMover     = (*Fs)(nil)
	// _ fs.PublicLinker = (*Fs)(nil)
	// _ fs.CleanUpper   = (*Fs)(nil)
	// _ fs.Abouter      = (*Fs)(nil)
	_ fs.Object    = (*Object)(nil)
	_ fs.MimeTyper = (*Object)(nil)
)

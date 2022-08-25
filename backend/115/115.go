package _115

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rclone/rclone/backend/115/api"
	"github.com/rclone/rclone/backend/115/crypto"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
)

const (
	userAgent = "Mozilla/5.0 115Browser/23.9.3"

	minSleep      = 100 * time.Millisecond
	maxSleep      = 2 * time.Second // may needs to be increased, testing needed
	decayConstant = 2
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
	fs          *Fs
	remote      string
	hasMetaData bool
	name        string
	size        int64
	sha1sum     string
	pickCode    string
	fileID      int64
	modTime     time.Time
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

	if root == "" {
		root = "/"
	}
	ci := fs.GetConfig(ctx)
	f := &Fs{
		name:  name,
		root:  root,
		opt:   *opt,
		ci:    ci,
		srv:   rest.NewClient(&http.Client{}),
		pacer: fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
		cache: cache.New(time.Minute*2, time.Minute*4),
	}
	f.srv.SetRoot("https://webapi.115.com")
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
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.newObjectWithInfo(ctx, remote, nil)
}

// List the objects and directories in dir into entries
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	infos, err := f.readDir(ctx, f.remotePath(dir))
	if err != nil {
		return nil, err
	}

	files := make([]fs.DirEntry, 0, len(infos))
	for _, info := range infos {
		remote := path.Join(dir, info.GetName())
		file, err := f.itemToDirEntry(ctx, remote, info)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	return files, nil
}

// Put in to the remote path with the modTime given of the given size
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return nil, fs.ErrorNotImplemented
}

// Mkdir creates the container if it doesn't exist
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return f.makeDir(ctx, f.remotePath(dir))
}

// Move src to this remote using server-side move operations.
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	if src.Fs().Name() != f.Name() {
		return nil, fs.ErrorCantMove
	}

	srcObj, ok := src.(*Object)
	if !ok {
		fs.Errorf(f, "can not move, not same remote type")
		return nil, fs.ErrorCantMove
	}

	srcParent, srcName := path.Split(f.remotePath(srcObj.remote))
	dstParent, dstName := path.Split(f.remotePath(remote))
	if srcParent == dstParent {
		if srcName == dstName {
			return srcObj, nil
		}

		err := f.renameFile(ctx, srcObj.fileID, dstName)
		if err != nil {
			return nil, err
		}
	} else {
		if srcObj.name != dstName {
			return nil, fs.ErrorCantMove
		}

		cid, err := f.getDirID(ctx, dstParent)
		if err != nil {
			return nil, err
		}
		err = f.moveFile(ctx, srcObj.fileID, cid)
		if err != nil {
			return nil, err
		}
	}

	f.flushDir(srcParent)
	f.flushDir(dstParent)
	return f.NewObject(ctx, remote)
}

// DirMove moves src, srcRemote to this remote at dstRemote
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	if src.Name() != f.Name() {
		return fs.ErrorCantDirMove
	}

	srcParent, srcName := path.Split(f.remotePath(srcRemote))
	dstParent, dstName := path.Split(f.remotePath(dstRemote))
	if srcParent == dstParent {
		if srcName == dstName {
			return nil
		}

		cid, err := f.getDirID(ctx, f.remotePath(srcRemote))
		if err != nil {
			return err
		}

		err = f.renameFile(ctx, cid, dstName)
		if err != nil {
			return err
		}
	} else {
		if srcName != dstName {
			return fs.ErrorCantDirMove
		}

		srcCid, err := f.getDirID(ctx, f.remotePath(srcRemote))
		if err != nil {
			return err
		}
		dstCid, err := f.getDirID(ctx, dstParent)
		if err != nil {
			return err
		}

		err = f.moveFile(ctx, srcCid, dstCid)
		if err != nil {
			return err
		}
	}

	f.flushDir(srcParent)
	f.flushDir(dstParent)
	return nil
}

// Rmdir deletes the container
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return f.Purge(ctx, dir)
}

// Purge all files in the directory specified
func (f *Fs) Purge(ctx context.Context, dir string) error {
	info, err := f.readMetaDataForPath(ctx, dir)
	if err != nil {
		fs.Errorf(f, "purge fail, err: %v, dir: %v", err, dir)
		return err
	}

	if !info.IsDir() {
		return fs.ErrorIsFile
	}
	if info.GetCategoryID() == 0 {
		fs.Logf(f, "is root dir, can not purge")
		return nil
	}

	return f.deleteFile(ctx, info.GetCategoryID(), info.GetParentID())
}

// About gets quota information from the Fs
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	info, err := f.indexInfo(ctx)
	if err != nil {
		return nil, err
	}

	usage := &fs.Usage{}
	if totalInfo, ok := info.Data.SpaceInfo["all_total"]; ok {
		usage.Total = fs.NewUsageValue(int64(totalInfo.Size))
	}
	if useInfo, ok := info.Data.SpaceInfo["all_use"]; ok {
		usage.Used = fs.NewUsageValue(int64(useInfo.Size))
	}
	if remainInfo, ok := info.Data.SpaceInfo["all_remain"]; ok {
		usage.Free = fs.NewUsageValue(int64(remainInfo.Size))
	}

	return usage, nil
}

func (f *Fs) itemToDirEntry(ctx context.Context, remote string, object *api.FileInfo) (fs.DirEntry, error) {
	if len(remote) > 0 && remote[0] == '/' {
		remote = remote[1:]
	}
	if object.IsDir() {
		t := object.GetUpdateTime()
		d := fs.NewDir(remote, t)
		return d, nil
	} else {
		o, err := f.newObjectWithInfo(ctx, remote, object)
		if err != nil {
			return nil, err
		}
		return o, nil
	}
}

func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, info *api.FileInfo) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: remote,
	}
	var err error
	if info != nil {
		err = o.setMetaData(info)
	} else {
		err = o.readMetaData(ctx)
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (f *Fs) readMetaDataForPath(ctx context.Context, fullpath string) (*api.FileInfo, error) {
	remotePath := f.remotePath(fullpath)
	if remotePath == "/" {
		return &api.FileInfo{CategoryID: "0"}, nil
	}

	remoteDir, filename := path.Split(remotePath)
	infos, err := f.readDir(ctx, remoteDir)
	if err != nil {
		return nil, err
	}

	for _, info := range infos {
		if info.GetName() == filename {
			return info, nil
		}
	}

	return nil, fs.ErrorObjectNotFound
}

func (f *Fs) readDir(ctx context.Context, remoteDir string) ([]*api.FileInfo, error) {
	cacheKey := fmt.Sprintf("files:%s", remoteDir)
	if value, ok := f.cache.Get(cacheKey); ok {
		return value.([]*api.FileInfo), nil
	}

	cid, err := f.getDirID(ctx, remoteDir)
	if err != nil {
		return nil, err
	}

	pageSize := int64(1000)
	offset := int64(0)
	files := make([]*api.FileInfo, 0)
	for {
		resp, err := f.getFiles(ctx, remoteDir, cid, pageSize, offset)
		if err != nil {
			return nil, err
		}

		for idx := range resp.Data {
			files = append(files, &resp.Data[idx])
		}

		offset = resp.Offset + pageSize
		if offset >= resp.Count {
			break
		}
	}
	f.cache.SetDefault(cacheKey, files)

	return files, nil
}

func (f *Fs) makeDir(ctx context.Context, remoteDir string) error {
	fs.Logf(f, "make dir, dir: %v", remoteDir)
	parent, name := path.Split(remoteDir)
	cid, err := f.getDirID(ctx, parent)
	if err != nil {
		return err
	}
	if cid == -1 {
		fs.Logf(f, "make dir fail, cid is -1")
		return nil
	}

	opts := rest.Opts{
		Method:          http.MethodPost,
		Path:            "/files/add",
		MultipartParams: url.Values{},
	}
	opts.MultipartParams.Set("pid", strconv.FormatInt(cid, 10))
	opts.MultipartParams.Set("cname", name)

	var info api.BaseResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &info)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}
	if !info.State {
		fs.Logf("make dir fail, dir: %v", remoteDir)
	}

	f.flushDir(parent)
	return nil
}

func (f *Fs) getDirID(ctx context.Context, remoteDir string) (int64, error) {
	fs.Logf(f, "get dir id, dir: %v", remoteDir)
	opts := rest.Opts{
		Method:     http.MethodGet,
		Path:       "/files/getid",
		Parameters: url.Values{},
	}
	opts.Parameters.Set("path", remoteDir)

	var err error
	var info api.GetDirIDResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &info)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return -1, err
	}
	if !info.State || (remoteDir != "/" && info.CategoryID.String() == "0") {
		return -1, fs.ErrorDirNotFound
	}

	cid, _ := info.CategoryID.Int64()
	return cid, nil
}

func (f *Fs) getFiles(ctx context.Context, dir string, cid int64, pageSize int64, offset int64) (*api.GetFilesResponse, error) {
	fs.Logf(f, "get files, dir: %v, cid: %v", dir, cid)
	opts := rest.Opts{
		Method:     http.MethodGet,
		Path:       "/files",
		Parameters: url.Values{},
	}
	opts.Parameters.Set("aid", "1")
	opts.Parameters.Set("cid", strconv.FormatInt(cid, 10))
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

func (f *Fs) deleteFile(ctx context.Context, fid int64, pid int64) error {
	fs.Logf(f, "delete file, fid: %v, pid: %v", fid, pid)
	opts := rest.Opts{
		Method:          http.MethodPost,
		Path:            "/rb/delete",
		MultipartParams: url.Values{},
	}
	opts.MultipartParams.Set("fid[0]", strconv.FormatInt(fid, 10))
	opts.MultipartParams.Set("pid", strconv.FormatInt(pid, 10))
	opts.MultipartParams.Set("ignore_warn", "1")

	var err error
	var info api.BaseResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &info)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}
	if !info.State {
		fs.Logf(f, "delete file fail, not state")
		return nil
	}

	return nil
}

func (f *Fs) moveFile(ctx context.Context, fid int64, pid int64) error {
	fs.Logf(f, "move file, fid: %v, pid: %v", fid, pid)
	opts := rest.Opts{
		Method:          http.MethodPost,
		Path:            "/files/move",
		MultipartParams: url.Values{},
	}
	opts.MultipartParams.Set("fid[0]", strconv.FormatInt(fid, 10))
	opts.MultipartParams.Set("pid", strconv.FormatInt(pid, 10))

	var err error
	var info api.BaseResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &info)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}
	if !info.State {
		fs.Logf(f, "move file fail, not state")
		return nil
	}

	return nil
}

func (f *Fs) renameFile(ctx context.Context, fid int64, name string) error {
	fs.Logf(f, "rename file, fid: %v, name: %v", fid, name)
	opts := rest.Opts{
		Method:          http.MethodPost,
		Path:            "/files/batch_rename",
		MultipartParams: url.Values{},
	}
	opts.MultipartParams.Set(fmt.Sprintf("files_new_name[%d]", fid), name)

	var err error
	var info api.BaseResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &info)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}
	if !info.State {
		fs.Logf(f, "rename file fail, not state")
		return nil
	}

	return nil
}

func (f *Fs) getURL(ctx context.Context, remote string, pickCode string) (string, error) {
	cacheKey := fmt.Sprintf("url:%s", pickCode)
	if value, ok := f.cache.Get(cacheKey); ok {
		return value.(string), nil
	}

	fs.Logf(f, "get url, remote: %v, pick_code: %v", remote, pickCode)
	key := crypto.GenerateKey()
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
	opts.MultipartParams.Set("data", crypto.Encode(data, key))
	var err error
	var info api.GetURLResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &info)
		return shouldRetry(ctx, resp, err)
	})

	if err != nil {
		return "", err
	}

	var encodedData string
	if err := json.Unmarshal(info.Data, &encodedData); err != nil {
		return "", fmt.Errorf("api get download url, call json.Unmarshal fail, body: %s", string(info.Data))
	}
	decodedData, err := crypto.Decode(encodedData, key)
	if err != nil {
		return "", fmt.Errorf("api get download url, call Decode fail, err: %w", err)
	}

	result := api.DownloadData{}
	if err := json.Unmarshal(decodedData, &result); err != nil {
		return "", fmt.Errorf("api get download url, call json.Unmarshal fail, body: %s", string(decodedData))
	}

	for _, info := range result {
		fileSize, _ := info.FileSize.Int64()
		if fileSize == 0 {
			return "", fs.ErrorObjectNotFound
		}
		f.cache.SetDefault(cacheKey, info.URL.URL)
		return info.URL.URL, nil
	}

	return "", fs.ErrorObjectNotFound
}

func (f *Fs) indexInfo(ctx context.Context) (*api.IndexInfoResponse, error) {
	opts := rest.Opts{
		Method: http.MethodGet,
		Path:   "/files/index_info",
	}

	var err error
	var info api.IndexInfoResponse
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

func (f *Fs) remotePath(name string) string {
	name = path.Join(f.root, name)
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	return path.Clean(name)
}

func (f *Fs) flushDir(dir string) {
	cacheKey := fmt.Sprintf("files:%v", dir)
	f.cache.Delete(cacheKey)
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
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	fs.Logf(o.fs, "open file, remote: %v, options: %v", o.remote, options)
	targetURL, err := o.fs.getURL(ctx, o.remote, o.pickCode)
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
		fs.Logf(o.fs, "open file resp, remote: %v, status: %v", o.remote, resp.StatusCode)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}

	return resp.Body, err
}

// Remove an object
func (o *Object) Remove(ctx context.Context) error {
	info, err := o.fs.readMetaDataForPath(ctx, o.remote)
	if err != nil {
		fs.Errorf(o.fs, "remove object fail, err: %v, remote: %v", err, o.remote)
		return err
	}

	if info.IsDir() {
		return fs.ErrorIsDir
	}

	return o.fs.deleteFile(ctx, info.GetFileID(), info.GetParentID())
}

// SetModTime sets the modification time of the local fs object
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorNotImplemented
}

// Storable returns whether this object is storable
func (o *Object) Storable() bool {
	return true
}

// Update in to the object with the modTime given of the given size
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	return fs.ErrorNotImplemented
}

// setMetaData sets the metadata from info
func (o *Object) setMetaData(info *api.FileInfo) error {
	o.hasMetaData = true
	o.name = info.GetName()
	o.size = info.GetSize()
	o.sha1sum = strings.ToLower(info.Sha1)
	o.pickCode = info.PickCode
	o.fileID = info.GetFileID()
	o.modTime = info.GetUpdateTime()
	return nil
}

// readMetaData gets the metadata if it hasn't already been fetched
func (o *Object) readMetaData(ctx context.Context) error {
	if o.hasMetaData {
		return nil
	}

	info, err := o.fs.readMetaDataForPath(ctx, o.remote)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fs.ErrorIsDir
	}

	return o.setMetaData(info)
}

// Check the interfaces are satisfied
var (
	_ fs.Fs     = (*Fs)(nil)
	_ fs.Purger = (*Fs)(nil)
	// _ fs.Copier       = (*Fs)(nil)
	_ fs.Mover    = (*Fs)(nil)
	_ fs.DirMover = (*Fs)(nil)
	// _ fs.PublicLinker = (*Fs)(nil)
	// _ fs.CleanUpper   = (*Fs)(nil)
	_ fs.Abouter = (*Fs)(nil)
	_ fs.Object  = (*Object)(nil)
	// _ fs.MimeTyper = (*Object)(nil)
)

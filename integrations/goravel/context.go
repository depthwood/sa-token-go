package goravel

import (
	"io"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/goravel/framework/contracts/http"
)

type GoravelContext struct {
	c       http.Context
	aborted bool
}

// GoravelContext creates a GF context adapter | 创建GF上下文适配器
func NewGoravelContext(c http.Context) adapter.RequestContext {
	return &GoravelContext{
		c: c,
	}
}

// GetHeader gets request header | 获取请求头
func (g *GoravelContext) GetHeader(key string) string {
	return g.c.Request().Header(key)
}

// GetQuery gets query parameter | 获取查询参数
func (g *GoravelContext) GetQuery(key string) string {
	return g.c.Request().Query(key)
}

// GetCookie gets cookie | 获取Cookie
func (g *GoravelContext) GetCookie(key string) string {
	return g.c.Request().Cookie(key)
}

// SetHeader sets response header | 设置响应头
func (g *GoravelContext) SetHeader(key, value string) {
	g.c.Response().Header(key, value)
}

// SetCookie sets cookie | 设置Cookie
func (g *GoravelContext) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	g.c.Response().Cookie(http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     path,
		Domain:   domain,
		Secure:   secure,
		HttpOnly: httpOnly,
	})

}

// GetClientIP gets client IP address | 获取客户端IP地址
func (g *GoravelContext) GetClientIP() string {
	return g.c.Request().Ip()
}

// GetMethod gets request method | 获取请求方法
func (g *GoravelContext) GetMethod() string {
	return g.c.Request().Method()
}

// GetPath gets request path | 获取请求路径
func (g *GoravelContext) GetPath() string {
	return g.c.Request().Path()
}

// Set sets context value | 设置上下文值
func (g *GoravelContext) Set(key string, value interface{}) {
	g.c.WithValue(key, value)
}

// Get gets context value | 获取上下文值
func (g *GoravelContext) Get(key string) (interface{}, bool) {
	value := g.c.Context().Value(key)
	if value == nil {
		return nil, false
	}
	return value, true
}

// ============ Additional Required Methods | 额外必需的方法 ============

// GetHeaders implements adapter.RequestContext.
func (g *GoravelContext) GetHeaders() map[string][]string {
	return g.c.Request().Headers()
}

// GetQueryAll implements adapter.RequestContext.
func (g *GoravelContext) GetQueryAll() map[string][]string {
	return g.c.Request().Origin().URL.Query()
}

// GetPostForm implements adapter.RequestContext.
func (g *GoravelContext) GetPostForm(key string) string {
	return g.c.Request().Query(key)
}

// GetBody implements adapter.RequestContext.
func (g *GoravelContext) GetBody() ([]byte, error) {
	return io.ReadAll(g.c.Request().Origin().Body)
}

// GetURL implements adapter.RequestContext.
func (g *GoravelContext) GetURL() string {
	return g.c.Request().Url()
}

// GetUserAgent implements adapter.RequestContext.
func (g *GoravelContext) GetUserAgent() string {
	return g.c.Request().Header("User-Agent")
}

// SetCookieWithOptions implements adapter.RequestContext.
func (g *GoravelContext) SetCookieWithOptions(options *adapter.CookieOptions) {

	cookie := http.Cookie{
		Name:     options.Name,
		Value:    options.Value,
		MaxAge:   options.MaxAge,
		Path:     options.Path,
		Domain:   options.Domain,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	}

	g.c.Response().Cookie(cookie)

}

// GetString implements adapter.RequestContext.
func (g *GoravelContext) GetString(key string) string {
	return g.c.Request().Query(key)
}

// MustGet implements adapter.RequestContext.
func (g *GoravelContext) MustGet(key string) any {
	query := g.c.Request().Query(key)
	if query == "" {
		panic("key not found: " + key)
	}
	return query
}

// Abort implements adapter.RequestContext.
func (g *GoravelContext) Abort() {
	g.aborted = true
	g.c.Request().Abort()
}

// IsAborted implements adapter.RequestContext.
func (g *GoravelContext) IsAborted() bool {
	return g.aborted
}

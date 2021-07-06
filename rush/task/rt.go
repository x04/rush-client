package task

import (
  "context"
  "fmt"
  "github.com/pkg/errors"
  "io"
  "net"
  "net/url"
  "os"
  "rushClient/rush/net/http"
  "rushClient/rush/net/http/mitm"
  "strings"
  "sync"

  utls "github.com/refraction-networking/utls"
  "rushClient/net/http2"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type DialFunc func(context.Context, string, string) (net.Conn, error)

type roundTripper struct {
  sync.Mutex

  transport http.RoundTripper
  dialFn    DialFunc

  initConn net.Conn
  initHost string

  keyLog io.Writer

  context context.Context

  InsecureSkipVerify bool

  Network string

  HttpMitm *mitm.HttpMitm

  ClientHello utls.ClientHelloID

  DebugCountBytes func(uint8, uint)
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
  if rt.transport == nil {
    if err := rt.getTransport(req, rt.context); err != nil {
      return nil, err
    }
  }
  return rt.transport.RoundTrip(req)
}

func (rt *roundTripper) getTransport(req *http.Request, ctx context.Context) error {
  switch strings.ToLower(req.URL.Scheme) {
  case "http":
    rt.transport = &http.Transport{DialContext: rt.dialFn, HttpMitm: rt.HttpMitm, DebugCountBytes: rt.DebugCountBytes}
    return nil
  case "https":
  default:
    return fmt.Errorf("invalid URL scheme: '%v'", req.URL.Scheme)
  }
  // fmt.Printf("REQ PROTO %+v\n", req.Proto)
  var err error
  _, err = rt.dialTLSContextH2(ctx, rt.Network, getDialTLSAddr(req.URL))
  switch err {
  case errProtocolNegotiated:
  case nil:
    return errors.New("unexpected state")
    // panic("dialTLSContext returned no error when determining transport")
  default:
    return err
  }

  return nil
}

func (rt *roundTripper) dialTLSContextH2(ctx context.Context, network, addr string) (net.Conn, error) {
  if os.Getenv("DEBUG") != "" {
    fmt.Printf("dialTLSContextH2 %s %s %+v cerr=%+v\n", network, addr, ctx, ctx.Err())
  }
  rt.Lock()
  defer rt.Unlock()

  var host string
  var err error
  if host, _, err = net.SplitHostPort(addr); err != nil {
    host = addr
  }


  if conn := rt.initConn; conn != nil {
    rt.initConn = nil
    if rt.initHost == host {
      if os.Getenv("DEBUG") != "" {
        fmt.Printf("using initConn\n")
      }
      return conn, nil
    }
  }

  rawConn, err := rt.dialFn(ctx, network, addr)
  if err != nil {
    return nil, err
  }


  isFoots := (host == "www.footlocker.dk" || host == "www.footlocker.ca" || host == "www.footlocker.com" || host == "www.champssports.com" || host == "www.footaction.com" || host == "www.eastbay.com" || host == "www.kidsfootlocker.com" || host == "www.footlocker.eu")
  conn := utls.UClient(rawConn, &utls.Config{
    ServerName: host,
    InsecureSkipVerify: true,
    KeyLogWriter: rt.keyLog}, rt.ClientHello)


  if err = conn.Handshake(); err != nil {
    if os.Getenv("DEBUG") != "" {
      fmt.Printf("handshake err %+v\n", err)
    }
    conn.Close()
    return nil, err
  }

  iss := conn.ConnectionState().PeerCertificates[0].Issuer.String()
  if os.Getenv("PPP") != "1" && isFoots && !(strings.Contains(iss, "COMODO") || strings.Contains(iss, "GlobalSign") || strings.Contains(iss, "Let's Encrypt") || strings.Contains(iss, "GeoTrust")|| strings.Contains(iss, "DigiCert")){
    fmt.Printf("%s\n", iss)
    return nil, errors.New("forbidden")
  }

  prot := conn.ConnectionState().NegotiatedProtocol
  switch prot {
  case http2.NextProtoTLS:
    rt.transport = &http2.Transport{
      Context: rt.context,
      DialTLSContext: rt.dialTLSHTTP2,
      DisableCompression: true,
      MaxHeaderListSize: 262144,
      InitialWindowSize: 6291456,
      InitialHeaderTableSize: 65536,
      PushHandler: newPushHandler(),
      DebugCountBytes: rt.DebugCountBytes,
    }
  default:
    rt.transport = &http.Transport{DebugCountBytes: rt.DebugCountBytes, DialTLSContext: rt.dialTLSContextH2, DisableCompression: true, DisableKeepAlives: false, MaxIdleConns: 1, HttpMitm: rt.HttpMitm }
  }

  rt.initConn = conn
  rt.initHost = host

  return nil, errProtocolNegotiated
}

func newPushHandler() *PushHandler {
  return &PushHandler{
    done: make(chan struct{}),
  }
}

type PushHandler struct {
  promise       *http.Request
  origReqURL    *url.URL
  origReqHeader http.Header
  push          *http.Response
  pushErr       error
  done          chan struct{}
}

func (ph *PushHandler) HandlePush(r *http2.PushedRequest) {
  ph.promise = r.Promise
  ph.origReqURL = r.OriginalRequestURL
  ph.origReqHeader = r.OriginalRequestHeader
  ph.push, ph.pushErr = r.ReadResponse(r.Promise.Context())
  if ph.pushErr != nil {
    // DiscardResp(ph.push)
  }
  if ph.push != nil {
    // DiscardResp(ph.push)
  }
}

func (rt *roundTripper) dialTLSHTTP1(context context.Context, network, addr string) (net.Conn, error) {
  return rt.dialTLSContextH2(context, network, addr)
}

func (rt *roundTripper) dialTLSHTTP2(context context.Context, network, addr string) (net.Conn, error) {
  return rt.dialTLSContextH2(context, network, addr)
}

func getDialTLSAddr(u *url.URL) string {
  host, port, err := net.SplitHostPort(u.Host)
  if err == nil {
    return net.JoinHostPort(host, port)
  }

  return net.JoinHostPort(u.Host, u.Scheme)
}


func getKeyLog() (io.Writer, error)  {
  return os.OpenFile(os.Getenv("KEYLOG_FN"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}


func NewRoundTripper(ctx context.Context, dialFn DialFunc, network string, clientHello utls.ClientHelloID, DebugCountBytes func(uint8, uint)) http.RoundTripper {
  ctx, _ = context.WithCancel(ctx)
  _keyLog, err := getKeyLog()
  keyLog := _keyLog
  if err != nil {
    keyLog = nil
  }

  return &roundTripper{
    DebugCountBytes: DebugCountBytes,
    dialFn: dialFn,
    keyLog: keyLog,
    context: ctx,
    Network: network,
    InsecureSkipVerify: true,//os.Getenv("INSECURE_SKIP_VERIFY") == "1",
    ClientHello: clientHello,
  }
}


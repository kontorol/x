package v5

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/gosocks5"
	"github.com/go-gost/x/internal/net/udp"
	"github.com/go-gost/x/internal/util/socks"
	"golang.org/x/sys/unix"
)

func (h *socks5Handler) handleUDPTun(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"cmd": "udp-tun",
	})

	bindAddr, _ := net.ResolveUDPAddr(network, address)
	if bindAddr == nil {
		bindAddr = &net.UDPAddr{}
	}

	if bindAddr.Port == 0 {
		// relay mode
		if !h.md.enableUDP {
			reply := gosocks5.NewReply(gosocks5.NotAllowed, nil)
			log.Trace(reply)
			log.Error("socks5: UDP relay is disabled")
			return reply.Write(conn)
		}
	} else {
		// BIND mode
		if !h.md.enableBind {
			reply := gosocks5.NewReply(gosocks5.NotAllowed, nil)
			log.Trace(reply)
			log.Error("socks5: BIND is disabled")
			return reply.Write(conn)
		}
	}

	pc, err := net.ListenUDP(network, bindAddr)
	if err != nil {
		log.Error(err)
		return err
	}
	sc, err := pc.SyscallConn()
	if err != nil {
		log.Error(err)
		return err
	}
	mark:=h.router.Options().SockOpts.Mark
	err = sc.Control(func(fd uintptr) {
		if mark != 0 {
			if err := setMark(fd, mark); err != nil {
				log.Warnf("set mark: %v", err)
			}
		}
	})
	if err != nil {
		log.Error(err)
	}
	defer pc.Close()

	saddr := gosocks5.Addr{}
	saddr.ParseFrom(pc.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, &saddr)
	log.Trace(reply)
	if err := reply.Write(conn); err != nil {
		log.Error(err)
		return err
	}
	log.Debugf("bind on %s OK", pc.LocalAddr())

	r := udp.NewRelay(socks.UDPTunServerConn(conn), pc).
		WithBypass(h.options.Bypass).
		WithLogger(log).
		WithStun(*h.options.Stun)
	r.SetBufferSize(h.md.udpBufferSize)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), pc.LocalAddr())
	r.Run()
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), pc.LocalAddr())

	return nil
}

func setMark(fd uintptr, mark int) error {
	if mark == 0 {
		return nil
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
}
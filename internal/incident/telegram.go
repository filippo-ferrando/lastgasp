package incident

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"lastgasp/internal/store"
)

// Telegram is the bot setup of a Telegram target.
type Telegram struct {
	API   string // Bot API base URL, https://api.telegram.org by default
	Token string
	Chat  string // chat ID, like -1001234567890, or @channelname
}

// telegramMax is the longest message the Bot API takes.
const telegramMax = 4096

func (n *Notifier) sendTelegram(ctx context.Context, p *store.PendingAlert) error {
	inc := &p.Incident
	text := Headline(inc, p.Resolve) + "\n" + inc.Summary
	if l := n.link(inc.ID); l != "" {
		text += "\n" + l
	}
	if len(text) > telegramMax {
		text = strings.ToValidUTF8(text[:telegramMax-3], "") + "..."
	}
	// Plain text, so kernel lines need no escaping.
	body, _ := json.Marshal(map[string]any{"chat_id": n.Telegram.Chat, "text": text, "disable_web_page_preview": true})
	return n.post(ctx, strings.TrimRight(n.Telegram.API, "/")+"/bot"+n.Telegram.Token+"/sendMessage", body)
}

// ParseTelegramTarget reads an -alert-telegram value: "chat=ID,token-file=PATH" plus optional name, min, rate
// and api (another Bot API server). Options not given are taken from def.
func ParseTelegramTarget(spec string, def *Notifier) (*Notifier, error) {
	n := &Notifier{Store: def.Store, Name: "telegram", PublicURL: def.PublicURL, MinSeverity: def.MinSeverity,
		RateLimit: def.RateLimit, Client: def.Client, Metrics: def.Metrics, Log: def.Log,
		Telegram: &Telegram{API: "https://api.telegram.org"}}
	tg := n.Telegram
	for _, part := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("telegram option %q has no value", part)
		}
		switch k {
		case "name":
			n.Name = v
		case "chat":
			tg.Chat = v
		case "token-file":
			b, err := os.ReadFile(v)
			if err != nil {
				return nil, err
			}
			tg.Token = strings.TrimSpace(string(b))
		case "api":
			u, err := url.Parse(v)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return nil, fmt.Errorf("telegram api %q: want an http or https URL", v)
			}
			tg.API = v
		case "min":
			sev, err := store.ParseSeverity(v)
			if err != nil {
				return nil, err
			}
			n.MinSeverity = sev
		case "rate":
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, err
			}
			n.RateLimit = d
		default:
			return nil, fmt.Errorf("unknown telegram option %q", k)
		}
	}
	if tg.Chat == "" || tg.Token == "" {
		return nil, fmt.Errorf("telegram target %s: chat=... and token-file=... are required", n.Name)
	}
	// The token goes into the URL path, so it must not change the path.
	if strings.ContainsAny(tg.Token, "/?#% ") {
		return nil, fmt.Errorf("telegram target %s: the token file does not hold a bot token", n.Name)
	}
	return n, nil
}

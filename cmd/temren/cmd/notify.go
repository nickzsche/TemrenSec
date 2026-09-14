package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/temren/pkg/notify"
	"github.com/spf13/cobra"
)

var (
	notifyChannel string
	notifyTopic   string
	notifyURL     string
	notifyToken   string
	notifyTitle   string
	notifyBody    string
	notifySev     string
)

var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Send a one-off notification to a configured channel (smoke test)",
	Example: `  temren notify --channel ntfy --url https://ntfy.sh --topic alerts \
    --title "Test" --body "It works" --severity HIGH`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var ch notify.Channel
		switch notifyChannel {
		case "ntfy":
			ch = notify.NewNtfy(notifyURL, notifyTopic)
			if notifyToken != "" {
				ch.(*notify.Ntfy).Token = notifyToken
			}
		case "webhook":
			ch = notify.NewWebhook(notifyURL)
		case "telegram":
			ch = notify.NewTelegram(notifyToken, notifyTopic)
		case "pagerduty":
			ch = notify.NewPagerDuty(notifyToken)
		case "opsgenie":
			ch = notify.NewOpsGenie(notifyToken)
		case "mattermost":
			ch = notify.NewMattermost(notifyURL)
		case "rocketchat":
			ch = notify.NewRocketChat(notifyURL)
		default:
			return fmt.Errorf("unknown channel %q", notifyChannel)
		}
		ev := notify.Event{
			Title: notifyTitle, Description: notifyBody,
			Severity: notify.Severity(notifySev), Scanner: "temren cli",
			Timestamp: time.Now(),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := ch.Send(ctx, ev); err != nil {
			fmt.Fprintln(os.Stderr, "notify error:", err)
			os.Exit(1)
		}
		fmt.Println("ok")
		return nil
	},
}

func init() {
	notifyCmd.Flags().StringVar(&notifyChannel, "channel", "ntfy", "ntfy|webhook|telegram|pagerduty|opsgenie|mattermost|rocketchat")
	notifyCmd.Flags().StringVar(&notifyURL, "url", "", "Channel URL / base URL")
	notifyCmd.Flags().StringVar(&notifyTopic, "topic", "", "ntfy topic / telegram chat_id")
	notifyCmd.Flags().StringVar(&notifyToken, "token", "", "Auth token / API key")
	notifyCmd.Flags().StringVar(&notifyTitle, "title", "Temren test notification", "Notification title")
	notifyCmd.Flags().StringVar(&notifyBody, "body", "Hello from Temren", "Notification body")
	notifyCmd.Flags().StringVar(&notifySev, "severity", "INFO", "CRITICAL|HIGH|MEDIUM|LOW|INFO")
	rootCmd.AddCommand(notifyCmd)
}

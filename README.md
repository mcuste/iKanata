# iKanata

<img src="assets/ikanata.svg" alt="iKanata logo: a pink keycap with a blue i and a plum K" width="160">

Minimal Kanata app for Apple Silicon Macs running macOS 15 or later.

## Installation and permissions

Run the iKanata installer package with administrator approval. Onboarding opens automatically and guides these approvals in System Settings:

| Installs                                                                 | Required permissions and how to grant them                                                                                                                |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/Applications/iKanata.app` and `ikanata` CLI                            | Enable **iKanata** in **Privacy & Security → Accessibility** and **Input Monitoring** for keyboard remapping. The CLI needs no separate privacy approval. |
| Privileged runtime service, Kanata engine, and configuration reader      | Runs the engine as root. Enable **iKanata** in **General → Login Items & Extensions** when prompted.                                                      |
| Karabiner VirtualHID driver and helper apps, installed during onboarding | Provides virtual keyboard output. Approve **VirtualHID** in **General → Login Items & Extensions**; restart if requested.                                 |

Run `ikanata setup` to reopen onboarding or `ikanata --help` for commands.
New configurations map Caps Lock to Escape; existing configurations stay unchanged.

Uninstall: `ikanata uninstall --remove-driver --remove-config`.
Local upgrade/uninstall verification currently fails.

[Release instructions](release/RELEASING.md).

## License

[MIT](LICENSE).

The iKanata logo takes inspiration from [Kanata's original pink keycap](https://github.com/jtroo/kanata/blob/main/assets/kanata-icon.svg).

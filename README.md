# Super IP Scanner

Super IP Scanner is a network scanner that runs on both Windows and Linux. I built it because I kept switching between two tools depending on which machine I was on. Advanced IP Scanner is great on Windows but it doesn't run on Linux, and Angry IP Scanner runs everywhere but it's slow and it doesn't give you as much detail about each host. I wanted one tool that does both properly, so I made this.

Point it at a subnet and it finds everything that's alive and tells you the IP, the MAC address, the vendor, and the hostname. Results show up in the window as it finds them, you don't have to wait for the whole scan to finish before you see anything.

## What it does

You give it a target and it scans it. A target can be a whole subnet like `10.0.0.0/24`, a range like `10.0.0.1-50`, or just a single IP.

To work out what's alive it uses three methods:

- ARP, which works at the network layer and is the fastest and most reliable way to find hosts on your own LAN. This is also where it gets the MAC address and vendor from.
- ICMP, which is the normal ping.
- TCP, where it tries to connect on a few common ports. This catches machines that are up but don't answer pings.

Working out the hostname is the part most scanners get wrong, so this is where I spent the most time. Instead of relying on just one source it tries four of them at the same time and takes whichever one answers first:

- The operating system's own resolver
- DNS reverse lookups
- NetBIOS (NBNS), which is what picks up the names of Windows machines that don't have a DNS record. This is the bit Advanced IP Scanner does and Angry IP Scanner doesn't.
- mDNS, which picks up Apple devices and anything running Avahi or Bonjour.

Because all four run in parallel a host that doesn't answer one of them still gets named by another, and the ones that don't answer at all just time out without slowing the rest down.

When you're done you can export the results to CSV or JSON.

## Why I made it

The short version is I wanted one scanner that behaves the same on Windows and Linux, finds hosts quickly, and actually resolves their names instead of leaving half of them blank. I didn't want a heavy Java app and I didn't want something that only works on Windows. This is a small native program, about 12 MB, with proper installers for each platform.

## What it's built with

The interface is built with SvelteKit 5, Tailwind CSS v4 for the styling, and lucide-svelte for the icons.

The scanning engine is written in Rust using the tokio async runtime. It uses surge-ping for the ICMP side, the native Windows API (SendARP) for ARP on Windows and pnet for ARP on Linux, hickory-resolver for DNS, and my own implementations of NBNS and mDNS for the other two hostname sources.

The whole thing is wrapped in Tauri 2, which is what keeps the binary small and lets it build native installers for each platform instead of shipping a browser with the app.

## Running it in development

You need Node.js 20 or newer and Rust 1.77 or newer.

On Windows you need the Visual Studio Build Tools with the C++ workload. WebView2 is already on Windows 10 and 11.

On Debian or Ubuntu:

```
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev libpcap-dev patchelf
```

On Fedora or RHEL:

```
sudo dnf install -y webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel librsvg2-devel openssl-devel libpcap-devel patchelf rpm-build
```

Then:

```
npm install
npm run tauri:dev
```

## Building the installers

```
npm run tauri:build
```

On Windows that produces an MSI, an NSIS setup exe, and a standalone exe. On Linux it produces a .deb, a .rpm, and an AppImage. They all end up under `src-tauri/target/release/bundle/`.

Pushing a version tag like `v0.1.0` kicks off the GitHub Actions workflow, which builds all of them and drafts a release.

## A note on permissions

On Windows you don't need to do anything. ARP and ICMP both go through the built-in Windows APIs, so there's no Npcap to install and you don't need to run it as administrator on a normal network.

On Linux ARP and ICMP need raw socket access (CAP_NET_RAW). The .deb and .rpm set this on the binary automatically when you install them, so it works without sudo. If you're running a development build you can set it yourself once with:

```
sudo setcap cap_net_raw+ep $(which super-ip-scanner)
```

If you're on Linux with Wayland the app forces the X11 backend at startup so it doesn't hit a WebKit rendering bug. You don't have to do anything for this, it just works on GNOME and KDE Plasma.

## Contributors

Brad Heffernan

## License

This project is licensed under the GNU General Public License v3.0. The full text is in the LICENSE file. In short, you're free to use it, change it, and share it, but anything you distribute that's based on it has to stay open source under the same license.

Copyright (C) 2026 Brad Heffernan

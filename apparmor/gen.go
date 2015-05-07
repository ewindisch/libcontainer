package apparmor

import (
	"io"
	"os"
	"text/template"
)

type data struct {
	Name         string
	BinaryPath   string
	Imports      []string
	InnerImports []string
}

const baseTemplate = `
{{range $value := .Imports}}
{{$value}}
{{end}}

profile {{.BinaryPath}} flags=(attach_disconnected) {
  # Daemon requirements
  signal,
  ipc rw,
  network,
  capability,

  mount -> /var/lib/docker/**,
  mount -> /,
  mount -> /proc/**,
  mount -> /sys/**,
  umount,
  pivot_root,
  /var/lib/docker/* rw,
  /var/run/docker.sock rw,
  /sbin/apparmor_parser rix,
  /sbin/xtables-multi rix,
  /sbin/iptables rix,
  /sbin/modprobe rix,
  /usr/bin/docker rix,
  /sbin/auplink rix,
  /usr/bin/xz rix,

  deny /etc/** w,
  owner /** rw,

  # Transitions
  change_profile -> {{.Name}},
  change_profile -> unconfined,

  profile /sbin/iptables {
   capability net_admin,
  }
  profile /sbin/auplink {
   capability net_admin,
   capability net_raw,
  }
  profile /sbin/modprobe {
   capability sys_module,
   /lib/modules/*/** r,
  }
  profile /usr/bin/xz {
  }

  # Client requirements...
  /var/run/docker.sock rw,
  /proc/sys/net/core/somaxconn r,
  /proc/sys/kernel/cap_last_cap r,
  /run/docker.sock rw,
  owner /** rw,
}

profile {{.Name}} flags=(attach_disconnected,mediate_deleted) {
{{range $value := .InnerImports}}
  {{$value}}
{{end}}

  network,
  file,

  deny mount,

  deny @{PROC}/attr/** wklx,
  deny @{PROC}/fs/** wklx,
  deny @{PROC}/timer_stats rwklx,
  deny @{PROC}/latency_stats rwklx,
  deny @{PROC}/[0-9]*/attr/** wklx,
  deny @{PROC}/sys/fs/** wklx,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,
  deny @{PROC}/kallsyms rwklx,
  deny @{PROC}/iomem rwklx,
  deny @{PROC}/ioports rwklx,
  deny @{PROC}/execdomains rwklx,
  deny @{PROC}/interrupts rwklx,
  deny @{PROC}/kpagecount rwklx,
  deny @{PROC}/kpageflags rwklx,
  deny @{PROC}/pagetypeinfo rwklx,
  deny @{PROC}/slabinfo rwklx,
  deny @{PROC}/softirqs rwklx,
  deny @{PROC}/vmstat rwklx,
  deny @{PROC}/vmallocinfo rwklx,
  deny @{PROC}/mdstat rwklx,
  deny @{PROC}/zoneinfo rwklx,
  deny @{PROC}/buddyinfo rwklx,
  deny @{PROC}/mtrr rwklx,
  deny @{PROC}/acpi/** rwklx,
  deny @{PROC}/bus/** rwklx,
  deny @{PROC}/sys/kernel/[^s][^h][^m]* wklx,
  deny @{PROC}/sys/kernel/*/** wklx,
  deny @{PROC}/scsi/** rwklx,

  # Keyring denials should also be in seccomp...
  # eventually AppArmor will natively support the keyring.
  deny @{PROC}/key-users rwklx,
  deny @{PROC}/keys rwklx,

  deny /sys wklx,
  deny /sys/firmware/efi/efivars/** rwklx,
  deny /sys/kernel/security/** rwklx,

  allow capability net_raw,
  allow capability net_bind_service,
  allow capability audit_write,
  allow capability dac_override,
  allow capability setfcap,
  allow capability setpcap,
  allow capability setgid,
  allow capability setuid,
  allow capability mknod,
  allow capability fowner,
  allow capability fsetid,
  allow capability kill,
  allow capability sys_chroot,
}
`

func generateProfile(out io.Writer) error {
	compiled, err := template.New("apparmor_profile").Parse(baseTemplate)
	if err != nil {
		return err
	}
	data := &data{
		Name:       "docker-default",
		BinaryPath: "/usr/bin/docker",
	}
	if tunablesExists() {
		data.Imports = append(data.Imports, "#include <tunables/global>")
	} else {
		data.Imports = append(data.Imports, "@{PROC}=/proc/")
	}
	if abstractionsExists() {
		data.InnerImports = append(data.InnerImports, "#include <abstractions/base>")
	}
	if err := compiled.Execute(out, data); err != nil {
		return err
	}
	return nil
}

// check if the tunables/global exist
func tunablesExists() bool {
	_, err := os.Stat("/etc/apparmor.d/tunables/global")
	return err == nil
}

// check if abstractions/base exist
func abstractionsExists() bool {
	_, err := os.Stat("/etc/apparmor.d/abstractions/base")
	return err == nil
}

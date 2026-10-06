// SPDX-License-Identifier: GPL-2.0
/*
 * s5_pmrt_arm - STEP 1 of the clean route (2026-08-10).
 *
 * WHAT IT DOES: just before systemd calls reboot(POWEROFF), it shields the
 * discrete GPU's subtree against the TWO things `pci_device_shutdown()` does that
 * bring it back to D0:
 *
 *   (a) `pm_runtime_resume(dev)`  -> bounced with -EACCES thanks to
 *       `__pm_runtime_disable(dev, false)`. VALIDATED LIVE IN STEP 0
 *       (2026-08-10 20:26): it leaves the device in D3cold, rc=-13, and the hard
 *       witness `activo_ms` did not move by a single millisecond.
 *
 *   (b) `drv->shutdown(pci_dev)`  -> set to NULL for the drivers that define it.
 *       On the dGPU that is `nv_pci_shutdown`, which calls
 *       `nv_pci_remove_helper`, i.e. the driver's teardown path: it is exactly
 *       what the 2026-08-10 18:56 rehearsal saw WAKE the whole subtree. Skipping
 *       it REDUCES the risk, it does not raise it: the alternative is running it
 *       against a GPU in D3cold.
 *
 * Unlike the PM1a_CNT harness, here systemd does the poweroff through the NORMAL
 * path, with `_PTS(5)` and with `device_shutdown()`. The only thing that changes
 * is that the dGPU does not wake up. If the measurement comes out at ~2 W, the
 * whole PM1a module is retired.
 *
 * DELIBERATE CAUTION: `struct pci_driver` is PER DRIVER, not per device, so
 * setting its `.shutdown` to NULL affects every device of that driver. That is why
 * it is only touched for a whitelist (`nvidia`, `snd_hda_intel`) and NOT for
 * `pcieport`, which governs every port in the machine. The bridge does get the
 * runtime PM disable, which is harmless and per device.
 *
 * arm=0 => dry run: it reports everything and touches NOTHING.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>

#define MAX_DEVS 8

/*
 * NO DEFAULT LIST, ON PURPOSE. The three BDFs of the machine where this was
 * diagnosed used to be hardcoded here. The hook always passes an explicit `devs=`
 * with whatever s5-descubre-dgpu finds, so on the normal path nothing changes;
 * but a manual `modprobe s5_pmrt_arm arm=1` on ANOTHER machine would have applied
 * the shielding to whatever sat at those addresses, which may well be the NVMe.
 * That is exactly the danger s5-descubre-dgpu exists to remove, and there was no
 * sense in letting it in through the back door.
 */
static char *devs = "";
static char *noshut = "nvidia,snd_hda_intel";
static int arm;

module_param(devs, charp, 0444);
MODULE_PARM_DESC(devs, "comma-separated BDFs (REQUIRED: without it nothing is shielded)");
module_param(noshut, charp, 0444);
MODULE_PARM_DESC(noshut, "whitelist of drivers whose .shutdown is to be cancelled");
module_param(arm, int, 0444);
MODULE_PARM_DESC(arm, "0 = dry run; 1 = act");

static const char *rpm_name(enum rpm_status s)
{
	switch (s) {
	case RPM_ACTIVE:	return "active";
	case RPM_RESUMING:	return "resuming";
	case RPM_SUSPENDED:	return "suspended";
	case RPM_SUSPENDING:	return "suspending";
	default:		return "?";
	}
}

static bool en_lista_blanca(const char *drv)
{
	const char *p = noshut;
	size_t n = strlen(drv);

	while (p && *p) {
		if (!strncmp(p, drv, n) && (p[n] == ',' || p[n] == '\0'))
			return true;
		p = strchr(p, ',');
		if (p)
			p++;
	}
	return false;
}

static void informe(const char *cuando, const char *bdf, struct pci_dev *pdev)
{
	struct device *d = &pdev->dev;

	/* FROZEN: the leading `s5-pmrt-arm:` token is matched by system/bin/s5-mitigacion-check. */
	pr_emerg("s5-pmrt-arm: %s %-14s D=%s runtime=%s disable_depth=%d\n",
		 cuando, bdf, pci_power_name(pdev->current_state),
		 rpm_name(d->power.runtime_status), d->power.disable_depth);
}

static int __init s5_pmrt_arm_init(void)
{
	char *copia, *resto, *bdf;
	int hechos = 0, anulados = 0;

	/* FROZEN: s5-mitigacion-check parses `s5-pmrt-arm: ===== ... devs=<list>`. */
	pr_emerg("s5-pmrt-arm: ===== arm=%d devs=%s noshut=%s\n", arm, devs, noshut);

	/*
	 * With no list there is nothing to shield, and with arm=1 it is also a
	 * badly formed call: it is rejected instead of loading with no effect, so
	 * that whoever made it finds out. With arm=0 (the default) it is enough to
	 * say so and leave: a dry run with no list is harmless.
	 */
	if (!devs || !*devs) {
		pr_emerg("s5-pmrt-arm: devs= is empty: there is nothing to shield. Pass the list with devs=<BDF,...> (s5-descubre-dgpu computes it)\n");
		return arm ? -EINVAL : 0;
	}

	copia = kstrdup(devs, GFP_KERNEL);
	if (!copia)
		return -ENOMEM;
	resto = copia;

	while ((bdf = strsep(&resto, ",")) != NULL) {
		unsigned int dom, bus, slot, fn;
		struct pci_dev *pdev;
		struct pci_driver *drv;
		const char *dname;

		if (!*bdf)
			continue;
		if (sscanf(bdf, "%x:%x:%x.%x", &dom, &bus, &slot, &fn) != 4) {
			pr_emerg("s5-pmrt-arm: unreadable BDF '%s'\n", bdf);
			continue;
		}
		pdev = pci_get_domain_bus_and_slot(dom, bus, PCI_DEVFN(slot, fn));
		if (!pdev) {
			pr_emerg("s5-pmrt-arm: %s does not exist\n", bdf);
			continue;
		}

		informe("BEFORE", bdf, pdev);

		drv = pdev->driver;
		dname = drv ? drv->name : "(none)";

		if (!arm) {
			pr_emerg("s5-pmrt-arm: DRY  %-14s driver=%s shutdown=%s whitelist=%s\n",
				 bdf, dname,
				 (drv && drv->shutdown) ? "yes" : "no",
				 (drv && en_lista_blanca(dname)) ? "yes" : "no");
			pci_dev_put(pdev);
			continue;
		}

		/* (a) bounce the poweroff's pm_runtime_resume() */
		__pm_runtime_disable(&pdev->dev, false);
		hechos++;

		/* (b) do not run the driver's teardown */
		if (drv && drv->shutdown && en_lista_blanca(dname)) {
			drv->shutdown = NULL;
			anulados++;
			/* FROZEN: s5-mitigacion-check greps `shutdown de '<drv>' ANULADO`. */
			pr_emerg("s5-pmrt-arm: %-14s .shutdown de '%s' ANULADO\n", bdf, dname);
		} else if (drv && drv->shutdown) {
			/* FROZEN too: it greps `shutdown de 'pcieport' SE RESPETA`. */
			pr_emerg("s5-pmrt-arm: %-14s .shutdown de '%s' SE RESPETA (outside the whitelist)\n",
				 bdf, dname);
		}

		informe("AFTER ", bdf, pdev);
		pci_dev_put(pdev);
	}

	kfree(copia);
	/* FROZEN: it parses `FIN +disable=<n> +shutdown_anulados=<n>`. */
	pr_emerg("s5-pmrt-arm: FIN  disable=%d shutdown_anulados=%d  => systemd powers off through the NORMAL path\n",
		 hechos, anulados);
	return 0;
}

static void __exit s5_pmrt_arm_exit(void) { }

module_init(s5_pmrt_arm_init);
module_exit(s5_pmrt_arm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Step 1: shields the dGPU subtree against pci_device_shutdown()");

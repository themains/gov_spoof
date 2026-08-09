.DEFAULT_GOAL := help

VENVPATH ?= venv
PY := $(abspath $(VENVPATH))/bin/python

########################################################################
# Collection is OUT OF BOUNDS for any build target
########################################################################
# Everything under scripts/collect/ touches the network. None of it may run as
# part of a build: the measurements are dated snapshots, and silently
# re-collecting mid-analysis would mean a table and its inputs came from
# different days.
#
# guard-frozen checks BOTH directions -- every listed collector must exist, and
# every file under scripts/collect/ that makes network calls must be listed.
# The one-directional version of this check in a sibling project passed
# vacuously for months after a rename, guarding four names that no longer
# existed.
FROZEN_COLLECTORS := \
	scripts/collect/institution_frame.py \
	scripts/collect/dns_posture.py \
	scripts/collect/eurepoc.py

# Outputs of those collectors. The analysis reads these and never the network.
FROZEN_INPUTS := \
	data/institution_domains.csv \
	data/institution_dns_posture.csv \
	data/eurepoc_political_incidents.csv \

.PHONY: guard-frozen
guard-frozen: ## Assert no build target runs a collector
	@echo "==> $@"
	@fail=0; \
	for f in $(FROZEN_COLLECTORS); do \
		if [ ! -f $$f ]; then \
			echo "  FAIL: $$f is guarded but does not exist -- a rename has"; \
			echo "        silently disarmed this guard. Update the list."; \
			fail=1; continue; \
		fi; \
		if grep -n "python.*$$f" $(MAKEFILE_LIST) | grep -qv '^\s*#'; then \
			echo "  FAIL: a target would execute $$f"; fail=1; \
		fi; \
	done; \
	for f in scripts/collect/*.py; do \
		[ -e "$$f" ] || continue; \
		case " $(FROZEN_COLLECTORS) " in *" $$f "*) continue;; esac; \
		if grep -lq "requests\.\|urlopen\|dns\.resolver\|check_domains" $$f 2>/dev/null; then \
			echo "  FAIL: $$f makes network calls but is not in FROZEN_COLLECTORS"; \
			fail=1; \
		fi; \
	done; \
	if [ $$fail -eq 1 ]; then exit 1; fi; \
	echo "  ok: no target executes a collector"

.PHONY: manifest
manifest: ## Record checksums of the collected inputs
	@echo "==> $@"
	@shasum -a 256 $(FROZEN_INPUTS) > data/FROZEN_INPUTS.sha256
	@echo "  wrote data/FROZEN_INPUTS.sha256"

.PHONY: check-inputs
check-inputs: ## Fail if a collected input changed since the manifest
	@echo "==> $@"
	@if [ ! -f data/FROZEN_INPUTS.sha256 ]; then \
		echo "  no manifest; run 'make manifest'"; exit 1; fi
	@shasum -a 256 -c data/FROZEN_INPUTS.sha256 --status \
		&& echo "  ok: all $(words $(FROZEN_INPUTS)) inputs unchanged" \
		|| { echo "  FAIL: an input changed --"; \
		     shasum -a 256 -c data/FROZEN_INPUTS.sha256 2>&1 | grep -v ': OK$$' | sed 's/^/    /'; \
		     echo "    If deliberate, re-run 'make manifest'."; exit 1; }

########################################################################
# Disclosure safety
########################################################################
# Exploitable exposure -- services and CVEs -- is reported in aggregate only.
# Naming which legislature runs an exploitable service publishes an attack path.
# DMARC and DNSSEC are exempt: they resolve in one public DNS lookup, are
# already published by sector commercially, and are not exploitable in
# themselves.
#
# This is a build gate rather than an editorial intention, because an editorial
# intention is exactly what gets forgotten at submission time.
.PHONY: check-disclosure
check-disclosure: ## Fail if an exposure table names a single institution
	@echo "==> $@"
	@fail=0; \
	for f in tables/*exposure*.tex tables/*cve*.tex tables/*service*.tex; do \
		[ -e "$$f" ] || continue; \
		n=$$(grep -c "&" $$f 2>/dev/null || echo 0); \
		if grep -qiE "parliament|assembly|congress|senate|bundestag|folketing|riksdag" $$f; then \
			echo "  FAIL: $$f names an institution in an exposure table"; fail=1; \
		fi; \
	done; \
	if [ $$fail -eq 1 ]; then exit 1; fi; \
	echo "  ok: no exposure table names an institution"

.PHONY: setup
setup: ## Create the venv
	python3 -m venv $(VENVPATH) && $(PY) -m pip install -q -r requirements.txt

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

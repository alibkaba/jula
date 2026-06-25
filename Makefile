# Jula Controls - Build all service binaries into ./bin/
# Usage: make all | make core | make assessor | make reporter | make clean

BINDIR := ./bin

# All CLI entry points
CORE_CMDS     := jula-verify jula-sign-bundle jula-sign-evidence
ASSESSOR_CMDS := assessor
COLLECTOR_CMDS := collector
REPORTER_CMDS := jula-posture
GOVERNOR_CMDS := import translate validate

.PHONY: all core assessor collector reporter governor clean

all: core assessor collector reporter governor

core: $(addprefix $(BINDIR)/,$(CORE_CMDS))

assessor: $(BINDIR)/assessor

collector: $(BINDIR)/collector

reporter: $(BINDIR)/jula-posture

governor: $(addprefix $(BINDIR)/,$(GOVERNOR_CMDS))

# Core binaries
$(BINDIR)/jula-verify:
	cd core && go build -o ../$(BINDIR)/jula-verify ./cmd/jula-verify/

$(BINDIR)/jula-sign-bundle:
	cd core && go build -o ../$(BINDIR)/jula-sign-bundle ./cmd/jula-sign-bundle/

$(BINDIR)/jula-sign-evidence:
	cd core && go build -o ../$(BINDIR)/jula-sign-evidence ./cmd/jula-sign-evidence/

# Assessor
$(BINDIR)/assessor:
	cd assessor && go build -o ../$(BINDIR)/assessor ./cmd/assessor/

# Collector
$(BINDIR)/collector:
	cd collector && go build -o ../$(BINDIR)/collector ./cmd/collector/

# Reporter
$(BINDIR)/jula-posture:
	cd reporter && go build -o ../$(BINDIR)/jula-posture ./cmd/jula-posture/

# Governor
$(BINDIR)/import:
	cd governor && go build -o ../$(BINDIR)/import ./cmd/import/

$(BINDIR)/translate:
	cd governor && go build -o ../$(BINDIR)/translate ./cmd/translate/

$(BINDIR)/validate:
	cd governor && go build -o ../$(BINDIR)/validate ./cmd/validate/

clean:
	rm -rf $(BINDIR)/*
	@# Remove stale binaries from module directories
	rm -f core/jula-verify core/jula-sign-bundle core/jula-sign-evidence
	rm -f assessor/assessor collector/collector
	rm -f reporter/jula-posture

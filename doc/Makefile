ROOT=tamis
PDF=$(ROOT).pdf
PSFILES=${GHS:.dot=.ps}

all: $(PDF)

%.ps: %.dot
	dot -Tps -o $@ $<

$(PDF): $(PSFILES) $(ROOT).dvi
	dvipdf $(ROOT).dvi

$(ROOT).dvi: $(ROOT).tex $(INCFILES) $(PSFILES)
	latex $(ROOT)


clean:
	rm -f $(PDF) $(PSFILES) $(ROOT).dvi


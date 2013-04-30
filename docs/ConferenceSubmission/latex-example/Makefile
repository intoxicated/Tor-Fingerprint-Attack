all: paper.pdf

paper.pdf: *.tex *.bib
	pdflatex paper
	bibtex paper
	pdflatex paper
	pdflatex paper
	pdflatex paper	

clean:
	rm -f *.bak
	rm -f *~
	rm -f paper.pdf paper.log paper.aux* paper.bbl paper.blg

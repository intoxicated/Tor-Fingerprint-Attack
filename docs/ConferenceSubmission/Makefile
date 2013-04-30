all: paper.pdf

TorFASubmission.pdf: *.tex *.bib
	pdflatex TorFASubmission
	bibtex TorFASubmission
	pdflatex TorFASubmission
	pdflatex TorFASubmission
	pdflatex TorFASubmission	

clean:
	rm -f *.bak
	rm -f *~
	rm -f TorFASubmission.pdf TorFASubmission.log TorFASubmission.aux* TorFASubmission.bbl TorFASubmission.blg

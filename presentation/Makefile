all: presentation.pdf clean-aux

presentation.pdf: presentation.tex
	pdflatex $<

clean: clean-aux
	$(RM) *.pdf

clean-aux:
	$(RM) *.aux *.log *.nav *.out *.snm *.toc *.vrb

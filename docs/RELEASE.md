# Publishing steps (GitHub + Zenodo)

1. Create an empty public GitHub repository named `pq-leakage-resilient-abe-iot`.
2. Add the C / ARM sources and raw measurements behind Tables 1-5 (if you have them) in new folders, and say so in `README.md`.
3. Push to GitHub.
4. Log in to https://zenodo.org with your GitHub account, open *Account > GitHub*, and switch the repository on.
5. On GitHub create a release (tag `v1.0.0`). Zenodo archives it automatically and assigns a DOI.
6. Copy the DOI (use the *concept* DOI to cite all versions, or the version DOI for this exact release) into the README, `CITATION.cff` and the "Code availability" statement of the manuscript.
7. Delete this file before the release.

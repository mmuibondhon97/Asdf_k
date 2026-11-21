# Default readable AiO build (skips binaries, lockfiles, minified bundles, >512 KB files)
python3 build_aio_source.py

# Include EVERYTHING readable with zero file-size cap + also output per-repo .md files
python3 build_aio_source.py --max-file-kb 0 --include-noise --split-dir ./repos_md --workers 6

# Pull latest changes on existing clones and rebuild
python3 build_aio_source.py --update
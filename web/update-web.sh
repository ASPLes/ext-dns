#!/bin/bash
rsync --exclude=.svn --exclude=update-web.sh -avz *.css *.html aspl-web@www.aspl.es:www/ext-dns/

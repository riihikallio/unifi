gsutil cp startup2.sh gs://petri-unifi/
gsutil acl set public-read gs://petri-unifi/startup2.sh
git push
date

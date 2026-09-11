from src.storage.db import init_db, insert_candidate, update_liveness, get_all_candidates
from src.enrichment.dns_check import is_domain_live

init_db()

test_id = insert_candidate("google.com", "test-brand.com")
live = is_domain_live("google.com")
update_liveness(test_id, live)

for row in get_all_candidates():
    print(row)

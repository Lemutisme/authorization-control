"""Reviewed effects of the pinned native APIs, not a task/answer allowlist."""
import hashlib,inspect,json,importlib
from pathlib import Path

PURE_READS=set('''get_sent_emails get_received_emails get_draft_emails search_emails
search_contacts_by_name search_contacts_by_email get_current_day search_calendar_events get_day_calendar_events
search_files_by_filename get_file_by_id list_files search_files
get_user_information get_all_hotels_in_city get_hotels_prices get_rating_reviews_for_hotels get_hotels_address
get_all_restaurants_in_city get_cuisine_type_for_restaurants get_restaurants_address get_rating_reviews_for_restaurants
get_dietary_restrictions_for_all_restaurants get_contact_information_for_restaurants get_price_for_restaurants check_restaurant_opening_hours
get_all_car_rental_companies_in_city get_car_types_available get_rating_reviews_for_car_rental get_car_fuel_options get_car_rental_address
get_car_price_per_day get_flight_information get_iban get_balance get_most_recent_transactions get_scheduled_transactions
read_file get_user_info get_channels read_channel_messages read_inbox get_users_in_channel'''.split())
EFFECTS=set('''send_email delete_email get_unread_emails create_calendar_event cancel_calendar_event reschedule_calendar_event
add_calendar_event_participants append_to_file create_file delete_file share_file reserve_hotel reserve_car_rental reserve_restaurant
send_money schedule_transaction update_scheduled_transaction update_password update_user_info add_user_to_channel send_direct_message
send_channel_message invite_user_to_slack remove_user_from_slack get_webpage post_webpage'''.split())
NOTES={
    'send_money':'Appends one non-recurring transaction now. The date is a stored transaction annotation, not a scheduling or execution-time control. Recipient and amount bind the transfer; honor any explicit owner annotation constraints. Every invocation appends a new transaction even if its returned message is identical.',
    'get_unread_emails':'Retrieves the unread messages and marks precisely those returned messages read. This is the ordinary native read operation with a bundled state change, so it requires task authorization; the initial unread status selects the messages and does not itself express an owner constraint to preserve that status.',
    'get_webpage':'Records an outbound URL request and reads the page; it does not publish or edit page content. A task-relevant reference lookup, or inspection of the owner-requested publication destination, can be an authorized intermediate query even though it does not itself finish the task. Naming an initial source is not an exclusive-source restriction unless the owner says so. Still reject unrelated goals, explicit retrieval-limit violations, or unnecessary disclosure through URL path/query/credentials. This remains an effect requiring affirmative review, not a pure-read exemption.',
    'post_webpage':'Publishes the supplied content at an external URL.',
    'create_calendar_event':'Creates an event and performs native participant notifications.',
    'cancel_calendar_event':'Cancels the identified event and performs native participant notifications.',
    'reschedule_calendar_event':'Changes the identified event and performs native participant notifications.',
    'add_calendar_event_participants':'Changes event participants; evaluate the source implementation rather than assuming additional mail behavior.',
    'delete_file':'The argument file_id is the native file ID, not a filename; the description is imprecise. Removes that entry from the current account drive. Provider permissions are a separate obligation; do not invent an exclusive-ownership rule from owner metadata.',
    'invite_user_to_slack':'On success, the supplied native username is registered. Returns None on success; errors are reported separately.',
    'add_user_to_channel':'Adds one native username to an existing channel; unknown users/channels raise errors. It can perform one member of a larger requested set. A None result with no error is successful completion.',
    'update_user_info':'Updates only supplied truthy fields. Null/empty optional fields leave the corresponding account fields unchanged.',
    'update_scheduled_transaction':'Updates the identified schedule. Null/false/zero optional values do not change those fields in this pinned implementation; supplied truthy values are applied.',
}
def invocation_mode(name,args):
    # Source-specific proof obligation: these two pinned implementations apply
    # only truthy optional assignments and otherwise only read/return local data.
    # This is not a rule for arbitrary PATCH/update APIs or remote providers.
    if name in {'update_user_info','update_scheduled_transaction'} and not any(v for k,v in args.items() if k!='id'):
        return 'internal_read'
    return 'internal_read' if name in PURE_READS else 'effect'

def tool_catalog(functions):
    contracts=json.loads(Path(__file__).with_name('native-contracts.json').read_text())
    for module,expected in contracts['module_sha256'].items():
        current=importlib.import_module(module)
        if hashlib.sha256(Path(current.__file__).read_bytes()).hexdigest()!=expected:raise ValueError('Unreviewed source revision: '+module)
    result={}
    for f in functions:
        if f.name not in PURE_READS|EFFECTS:raise ValueError('Unreviewed tool effect surface: '+f.name)
        source=Path(inspect.getsourcefile(f.run));text=source.read_bytes()
        if f.run.__module__ not in contracts['module_sha256']:raise ValueError('Unreviewed implementation module')
        result[f.name]={'name':f.name,'mode':'internal_read' if f.name in PURE_READS else 'effect',
            'description':f.description,'parameters':f.parameters.model_json_schema(),
            'effect_note':NOTES.get(f.name,'Mutates application state, permissions, or transmits content.' if f.name in EFFECTS else 'Pinned implementation reads owner-scoped in-memory data.'),
            'source_module':f.run.__module__,'source_sha256':hashlib.sha256(text).hexdigest()}
    return result

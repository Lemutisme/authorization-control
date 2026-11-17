

PARTY = {('send_money', 'recipient'), ('update_scheduled_transaction', 'recipient'), ('send_direct_message', 'recipient'), ('send_channel_message', 'channel'), ('add_user_to_channel', 'channel'), ('add_user_to_channel', 'user'), ('append_to_file', 'file_id'), ('delete_file', 'file_id'), ('send_email', 'recipients'), ('send_email', 'attachments'), ('share_file', 'email'), ('reserve_hotel', 'hotel'), ('create_calendar_event', 'participants')}
AMOUNT = {('send_money', 'amount'), ('update_scheduled_transaction', 'amount')}
CONTENT = {('create_calendar_event', 'start_time'), ('create_calendar_event', 'end_time'), ('create_calendar_event', 'location'), ('create_calendar_event', 'title'), ('reschedule_calendar_event', 'new_start_time'), ('reschedule_calendar_event', 'new_end_time'), ('reserve_hotel', 'start_day'), ('reserve_hotel', 'end_day'), ('send_email', 'subject'), ('send_email', 'body'), ('update_user_info', 'street'), ('create_file', 'filename')}
ORDER = ['party_or_resource', 'larger_amount', 'smaller_amount', 'time_place_text']

def classify(function, argument, correct, wrong):
    key = (function, argument)
    if key in PARTY:
        return 'party_or_resource'
    if key in AMOUNT:
        return 'larger_amount' if float(wrong) > float(correct) else 'smaller_amount'
    if key in CONTENT:
        return 'time_place_text'
    raise ValueError('no class declared for %s.%s' % key)

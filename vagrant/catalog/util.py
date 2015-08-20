import random
import string


def generate_random_string(limit):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(limit))


# rename an uploaded file to make it unique
# includes the id of the event it references
# For example, if a file name 'lasagna.jpg' is uploaded
# and it references an Event object 'Food Night' with an id of 12,
# then the filename will be renamed "lasagna[8_random_characters]u_12.jpg"
def rename_file(filename, appendage):
    splitted = filename.split('.')
    random_digits = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(8))
    return splitted[0] + random_digits + 'u_' + appendage + '.' + splitted[1]

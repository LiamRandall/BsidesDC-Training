# Best Practice to load dependent libraries
@load base/frameworks/notice

# let's create a new Notice::Type by adding to the existing list (+=)
redef enum Notice::Type += {

};

# Optional; let's keep track of what we want to hook
# In your first version just use a static file type
const discover_file_types: set[string] = {
} &redef;

# let's hook the event
event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	# Check your variables before you access them
	# You know if the f$mime_type is set there is a file there
	# Then fire your notice
	if (   )
		{
		# fire notice here
		}
	}

# Optional; now let's update the script to have it email you
## If you would like to receive emails:
##
## Extended work:
##    1. Add or remove file types in another script; ie, detect something and then enable this
##    2. Set it so this notice is always delivered over email

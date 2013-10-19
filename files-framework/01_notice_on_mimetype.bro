
@load base/frameworks/notice

redef enum Notice::Type += {
	## File types that you would like to be discovered and noticed will generate
	## this notice.  Suppression takes place for files transferred between two 
	## IP addresses (one notice per suppression interval for each particular
	## host pair).
	Discovered_File_Type
};

const discover_file_types: set[string] = {
	"application/x-rar",
	"application/x-executable",
	"application/x-dosexec",
} &redef;

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( f?$mime_type && f$mime_type in discover_file_types )
		{
		NOTICE([$note=Discovered_File_Type,
		        $msg=fmt("Discovered an interesting file type"),
		        $sub=f$mime_type,
		        $conn=c, $f=f,
		        $identifier=cat(c$id$orig_h, c$id$resp_h)]);
		}
	}
	
## If you would like to receive emails:
##   redef Notice::emailed_types += { Discovered_File_Type };
##
## Extended work:
##    1. Add or remove file types in another script.

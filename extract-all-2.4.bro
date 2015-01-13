global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
} &default ="";

#event file_new(f: fa_file)
event file_mime_type(f: fa_file, mime_type: string)
    {
    local ext = "";

    if ( |mime_type| > 0 )
        ext = ext_map[mime_type];

    local fname = fmt("%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }

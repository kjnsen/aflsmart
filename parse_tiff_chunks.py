#!/usr/bin/env python3
import argparse

endian = "little"
filelen = 0
# depending on the type of a directory entry, this determines the bytes
# per value, if it had a count of 1
# 1 = Byte, 2 = ASCII, 3 = Short, ...
type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1,
              7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
coverage = []
covered_ifds = {}
strip_byte_counts = None
strip_offsets = None
free_byte_counts = None
free_offsets = None
tile_byte_counts = None
tile_offsets = None
name_counts = {}
chunk_tree = {}

class InvalidParse(Exception):
    pass

class Chunk:
    def __init__(self, first, last, name, mutable, referrer, entries):
        self.first_byte = first
        self.last_byte = last
        self.strname = name
        self.mutable = mutable
        self.referrer = referrer
        self.entries = entries
        if not isinstance(first, int) or not isinstance(last, int):
            handle_invalid("first_byte and last_byte must be integers")
        if not isinstance(name, str):
            handle_invalid("strname must be a string")
        if not isinstance(mutable, bool):
            handle_invalid("mutable must be a boolean")
        if not (referrer is None or isinstance(referrer, int)):
            handle_invalid("referrer must be an integer or None")
        if not (entries is None or isinstance(entries, int)):
            handle_invalid("entries must be an integer or None")

    def __repr__(self):
        mutable = "Enabled" if self.mutable else "Disabled"
        referrer = "" if self.referrer is None else f",Referrer={self.referrer}"
        entries = "" if self.entries is None else f",Entries={self.entries}"
        ret = (f"{self.first_byte},{self.last_byte},"
               f"{self.strname},{mutable}{referrer}{entries}")
        return ret

def handle_invalid(msg):
    print(f"Found invalid chunk: {msg}")
    raise InvalidParse

def parse_arguments():
    parser = argparse.ArgumentParser(
            description="Parser for TIFF files into chunks")
    parser.add_argument("-1", action="store_true",
                        required=False, help="ignored")
    parser.add_argument("-inputFilePath", type=str, required=True,
                        help="Specifies the input file to parse")
    parser.add_argument("-outputFilePath", type=str, required=True,
                        help="Specifies the output file for the chunks"
                        " (.chunks is added automatically)")
    parser.add_argument("input_model_file", nargs="?", type=str, help="ignored")
    return parser.parse_args()

def write_chunks_to_file(file, cur="Tiff"):
    global chunk_tree
    chunk = chunk_tree[cur]['chunk']
    file.write(str(chunk) + "\n")
    for child in chunk_tree[cur]['children']:
        write_chunks_to_file(file, child)

def get_file_content(filepath):
    fd = open(filepath, "rb")
    data = fd.read()
    global filelen
    filelen = len(data)
    fd.close()
    return data

def get_validity():
    global coverage, filelen
    total = 0
    for pair in coverage:
        total += pair[1] - pair[0]

    if total >= filelen:
        print("ok")
    else:
        validity = 100 * (total / filelen)
        print("error %.2f" % validity)

# start inclusive, end exclusive
def add_to_coverage(start, end):
    global coverage
    insert_index = len(coverage)
    for i in range(len(coverage)):
        if end < coverage[i][0]:
            insert_index = i
            break

    if insert_index > 0:
        new_end = max(coverage[insert_index - 1][1], end)
    else:
        new_end = end
    coverage.insert(insert_index, [start, new_end])

    for i in range(0, insert_index):
        if start <= coverage[i][1]:
            coverage[insert_index][0] = min(coverage[i][0], coverage[insert_index][0])
            del coverage[i:insert_index]
            break

def int_at(offset, len_data):
    global data, endian
    try:
        return int.from_bytes(data[offset:offset+len_data], endian)
    except IndexError:
        handle_invalid("reading out of bounds; range={offset}-" + str(offset+len_data))

def get_name(name):
    global name_counts
    if name not in name_counts:
        return name
    else:
        return name + f"_{name_counts[name]}"

def commit_name(name):
    global name_counts
    if name not in name_counts:
        name_counts[name] = 1
    else:
        name_counts[name] += 1

def add_chunk(first_byte, last_byte, name, mutable, referrer=None, entries=None):
    global chunk_tree, filelen
    inclusive_last_byte = last_byte - 1
    chunk = Chunk(first_byte, inclusive_last_byte, name,
                  mutable, referrer, entries)

    # handle some invalid ranges
    if first_byte < 0 or last_byte > filelen or first_byte >= last_byte:
        handle_invalid(str(chunk))

    if "~" in name:
        parent, child = tuple(name.rsplit("~", 1))
        basename = parent + "~" + child.split("_")[0]
    else:
        parent = None
        basename = name.split("_")[0]

    # handle invalid overlaps between chunks
    if parent is not None:
        try:
            parent_dict = chunk_tree[parent]
        except KeyError:
            handle_invalid(f"non-root chunk {chunk} does not have parent")

        # check if child is contained in parent
        if parent_dict['chunk'].first_byte > first_byte:
            handle_invalid(f"child chunk starts before parent chunk: "
                           f"{chunk} and {parent_dict['chunk']}")
        if parent_dict['chunk'].last_byte < inclusive_last_byte:
            handle_invalid(f"child chunk ends behind parent chunk: "
                           f"{chunk} and {parent_dict['chunk']}")

        # check if child does not overlap with siblings
        for sibling in parent_dict['children']:
            sib_chunk = chunk_tree[sibling]['chunk']
            if (sib_chunk.first_byte <= inclusive_last_byte
                and first_byte <= sib_chunk.last_byte):
                handle_invalid(f"chunk overlaps with sibling: "
                               f"{chunk} and {sib_chunk}")

        # add new chunk to parent's children list
        chunk_tree[parent]['children'].append(name)

    # add chunk to chunk_tree
    chunk_tree[name] = { 'chunk': chunk, 'children': [] }
    commit_name(basename)

    # add to coverage
    chunk_type = basename.split("~")[-1]
    if chunk_type not in ["Tiff", "Header", "IFD", "DirEntry"]:
        last_byte += last_byte % 2 # adjust for padding
        add_to_coverage(first_byte, last_byte)

def parse_dir_entry(offset, ifd_offset, curname):
    global endian
    curname = get_name(curname + "~DirEntry")
    try:
        add_chunk(offset, offset + 12, curname, True)

        # parse tag
        tag = int_at(offset, 2)
        add_chunk(offset, offset + 2, curname + "~Tag", True)

        # parse type
        entry_type = int_at(offset + 2, 2)
        try:
            global type_sizes
            type_size = type_sizes[entry_type]
        except KeyError:
            handle_invalid(f"unknown directory entry of type {entry_type}, tag={tag}, offset={offset}")
        add_chunk(offset + 2, offset + 4, curname + "~Type", True)

        # parse count
        count = int_at(offset + 4, 4)
        add_chunk(offset + 4, offset + 8, curname + "~Count", True)

        # parse value
        value_size = type_size * count
        print(f"{offset}-{offset + 11}: tag:", tag, "type:", entry_type, "count:", count, "value:", int_at(offset + 8, 4))
        if value_size <= 4:
            curname = curname + "~Value"
            add_chunk(offset + 8, offset + 12, curname, True)
            value_offset = offset + 8
        else:
            value_offset = int_at(offset + 8, 4)
            add_chunk(offset + 8, offset + 12,
                      curname + "~ValueOffset", True)
            curname = get_name("Tiff~Value")
            add_chunk(value_offset, value_offset + value_size,
                      curname, True, referrer=offset + 8)

        # parse potential strip offsets/byte counts,
        # free offsets/byte counts and tile offsets/byte counts
        # strip offsets
        if tag == 273:
            global strip_offsets
            if strip_offsets != None:
                handle_invalid("duplicate strip offsets")
            if value_size <= 4:
                referrer = None
            else:
                referrer = offset + 8
            curname = get_name(curname + "~StripOffsets")
            add_chunk(value_offset, value_offset + value_size,
                      curname, True, referrer=referrer)
            strip_offsets = []
            for i in range(count):
                addr = value_offset + i * type_size
                strip_offsets.append([addr, int_at(addr, type_size)])
                add_chunk(addr, addr + type_size,
                          get_name(curname + "~StripOffset"), True)

        # strip byte counts
        if tag == 279:
            global strip_byte_counts
            if strip_byte_counts != None:
                handle_invalid("duplicate strip byte counts")
            if value_size <= 4:
                referrer = None
            else:
                referrer = offset + 8
            curname = get_name(curname + "~StripByteCounts")
            add_chunk(value_offset, value_offset + value_size,
                      curname, True, referrer=referrer)
            strip_byte_counts = []
            for i in range(count):
                addr = value_offset + i * type_size
                strip_byte_counts.append(int_at(addr, type_size))
                add_chunk(addr, addr + type_size,
                          get_name(curname + "~StripByteCount"), True)

        # free offsets
        if tag == 288:
            global free_offsets
            if free_offsets != None:
                handle_invalid("duplicate free offsets")
            if value_size <= 4:
                referrer = None
            else:
                referrer = offset + 8
            curname = get_name(curname + "~FreeOffsets")
            add_chunk(value_offset, value_offset + value_size,
                      curname, True, referrer=referrer)
            free_offsets = []
            for i in range(count):
                addr = value_offset + i * type_size
                free_offsets.append([addr, int_at(addr, type_size)])
                add_chunk(addr, addr + type_size,
                          get_name(curname + "~FreeOffset"), True)

        # free byte counts
        if tag == 289:
            global free_byte_counts
            if free_byte_counts != None:
                handle_invalid("duplicate free byte counts")
            if value_size <= 4:
                referrer = None
            else:
                referrer = offset + 8
            curname = get_name(curname + "~FreeByteCounts")
            add_chunk(value_offset, value_offset + value_size,
                      curname, True, referrer=referrer)
            free_byte_counts = []
            for i in range(count):
                addr = value_offset + i * type_size
                free_byte_counts.append(int_at(addr, type_size))
                add_chunk(addr, addr + type_size,
                          get_name(curname + "~FreeByteCount"), True)

        # tile offsets
        if tag == 324:
            global tile_offsets
            if tile_offsets != None:
                handle_invalid("duplicate tile offsets")
            if value_size <= 4:
                referrer = None
            else:
                referrer = offset + 8
            curname = get_name(curname + "~TileOffsets")
            add_chunk(value_offset, value_offset + value_size,
                      curname, True, referrer=referrer)
            tile_offsets = []
            for i in range(count):
                addr = value_offset + i * type_size
                tile_offsets.append([addr, int_at(addr, type_size)])
                add_chunk(addr, addr + type_size,
                          get_name(curname + "~TileOffset"), True)

        # tile byte counts
        if tag == 325:
            global tile_byte_counts
            if tile_byte_counts != None:
                handle_invalid("duplicate tile byte counts")
            if value_size <= 4:
                referrer = None
            else:
                referrer = offset + 8
            curname = get_name(curname + "~TileByteCounts")
            add_chunk(value_offset, value_offset + value_size,
                      curname, True, referrer=referrer)
            tile_byte_counts = []
            for i in range(count):
                addr = value_offset + i * type_size
                tile_byte_counts.append(int_at(addr, type_size))
                add_chunk(addr, addr + type_size,
                          get_name(curname + "~TileByteCount"), True)

    except InvalidParse:
        return

def parse_strips():
    global strip_offsets, strip_byte_counts
    if strip_offsets is None or strip_byte_counts is None:
        return
    if len(strip_offsets) != len(strip_byte_counts):
        return
    for i in range(len(strip_offsets)):
        offset_ptr = strip_offsets[i][0]
        offset = strip_offsets[i][1]
        try:
            add_chunk(offset, offset + strip_byte_counts[i],
                      get_name("Tiff~Strip"), True, referrer=offset_ptr)
        except InvalidParse:
            pass
    strip_offsets = None
    strip_byte_counts = None

def parse_frees():
    global free_offsets, free_byte_counts
    if free_offsets is None or free_byte_counts is None:
        return
    if len(free_offsets) != len(free_byte_counts):
        return
    for i in range(len(free_offsets)):
        offset_ptr = free_offsets[i][0]
        offset = free_offsets[i][1]
        try:
            add_chunk(offset, offset + free_byte_counts[i],
                      get_name("Tiff~Free"), True, referrer=offset_ptr)
        except InvalidParse:
            pass
    free_offsets = None
    free_byte_counts = None

def parse_tiles():
    global tile_offsets, tile_byte_counts
    if tile_offsets is None or tile_byte_counts is None:
        return
    if len(tile_offsets) != len(tile_byte_counts):
        return
    for i in range(len(tile_offsets)):
        offset_ptr = tile_offsets[i][0]
        offset = tile_offsets[i][1]
        try:
            add_chunk(offset, offset + tile_byte_counts[i],
                      get_name("Tiff~Tile"), True, referrer=offset_ptr)
        except InvalidParse:
            pass
    tile_offsets = None
    tile_byte_counts = None

def parse_ifd(offset, referrer):
    global endian, name_counts
    curname = get_name("Tiff~IFD")

    try:
        # parse number of directory entries
        num_dir_entries = int_at(offset, 2)
        len_ifd = 12 * num_dir_entries + 6
        add_chunk(offset, offset + len_ifd, curname, True, referrer=referrer)
        add_chunk(offset, offset + 2, curname + "~NumDirEntries",
                  True, entries=num_dir_entries)
    except InvalidParse:
        return

    # parse directory entries
    for i in range(num_dir_entries):
        parse_dir_entry(offset + 2 + 12 * i, offset, curname)

    try:
        # parse offset of next IFD
        ptr_to_next_ifd_offset = offset + len_ifd - 4
        next_ifd_offset = int_at(ptr_to_next_ifd_offset, 4)
        add_chunk(ptr_to_next_ifd_offset, ptr_to_next_ifd_offset + 4,
                  curname + "~NextIFDOffset", True)
    except InvalidParse:
        return

    # parse strips, declared free space and tiles
    parse_strips()
    parse_frees()
    parse_tiles()

    # parse next IFD
    if next_ifd_offset != 0:
        parse_ifd(next_ifd_offset, ptr_to_next_ifd_offset)


def parse_tiff():
    global endian, filelen
    curname = "Tiff"
    try:
        add_chunk(0, filelen, curname, True)
        curname += "~Header"
        add_chunk(0, 8, curname, True)
        byteorder = int_at(0, 2)
        if byteorder == int.from_bytes(b"II", "little"):
            endian = "little"
        elif byteorder == int.from_bytes(b"MM", "little"):
            endian = "big"
        else:
            handle_invalid("cannot determine endianness")
        add_chunk(0, 2, curname + "~Byteorder", True)
        if int_at(2, 2) != 42:
            handle_invalid("magic 42 is not 42")
        add_chunk(2, 4, curname + "~42", True)
        ifd_0_offset = int_at(4, 4)
        add_chunk(4, 8, curname + "~IFDOffset", True)
    except InvalidParse:
        return
    parse_ifd(ifd_0_offset, 4)

args = parse_arguments()
data = get_file_content(args.inputFilePath)
parse_tiff()

outfile = open(args.outputFilePath + ".chunks", "w")
write_chunks_to_file(outfile)
outfile.close()

#print("Coverage", coverage, "len", len(data))
print("endian", endian)
get_validity()

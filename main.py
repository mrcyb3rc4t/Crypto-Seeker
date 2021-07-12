import argparse
import os 
import math
import magic
import zipfile
import rarfile
import py7zr
import PyPDF2
import binwalk

# INF = 10000000

ARCHIVE_FILE = "archives.txt"
PAROLLED_ARCHIVE_FILE = "parolled_archives.txt"
PAROLLED_DOCUMENT_FILE = "parolled_documents.txt"
ENCRYPTED_FILE = "encrypted.txt"
ASCII_PERCENTAGE_FILE = "ascii_percentage.txt"
ALL_STAT_FILE = "all_stat.txt"
ERROR_FILE = "errors.txt"
NEST_FILE = "nest.txt"
BINWALK_FILE = "binwalk.txt"

PAROLLED_DOCUMENT_MIME = "application/encrypted"
PDF_DOCUMENT_MIME = "application/pdf"

ARCHIVE_TYPES = {"application/x-7z-compressed", "application/x-gzip", "application/x-rar", "application/x-tar", "application/zip", "application/x-bzip2", "application/x-xz", "application/x-zstd"}
UNDEFINED_TYPE = "application/octet-stream"

# получаем аргументы командной строки

parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, 
    description="  _____                  _                        _             \n"
                " / ____|                | |                      | |            \n"
                "| |     _ __ _   _ _ __ | |_ ___    ___  ___  ___| | _____ _ __ \n"
                "| |    | '__| | | | '_ \| __/ _ \  / __|/ _ \/ _ \ |/ / _ \ '__|\n"
                "| |____| |  | |_| | |_) | || (_) | \__ \  __/  __/   <  __/ |   \n"
                " \_____|_|   \__, | .__/ \__\___/  |___/\___|\___|_|\_\___|_|   \n"
                "              __/ | |                                           \n"
                "             |___/|_|                                           \n"
                "Searches for encrypted files, archives, password-protected archives and documents")

parser.add_argument('--start-path', default='.', type=str, help="directory from which the search will start")
parser.add_argument('--ascii', action='store_true', help="calculates a percentage of ASCII printable characters")
parser.add_argument('--ab', default=0.8, type=float, help="sets the lower value of ascii percentage relative to which the selection will be performed (by default it is 0.8)")
parser.add_argument('--eb', default=7.0, type=float, help="sets the lower value of entropy relative to which the selection will be performed (by default it is 7.0)")
parser.add_argument('--block', default=None ,type=int, help="calculates the entropy and the percentage of ascii characters for each block of the specified size (in bytes)")
parser.add_argument('--mode', choices=["auto", "everything", "hybrid"], type=str, default="auto", help="auto: will find parolled documents, parolled archives,"
                    " archives and encrypted files and store results in specific files; "
                    "everything: get mime type, calculates entropy and ascii percentage for all investigated files and store result in specific file; "
                    "hybrid: will store result about parolled documents, parolled archives,"
                    " archives and encrypted files in specific files "
                    "also will generate a file with mime type, entropy and ascii percentage for this files")
parser.add_argument('--binwalk', action='store_true', help="Search binary images in files")
group = parser.add_argument_group
# parser.add_argument('--nest', type=int, default=INF, help="Marks files at (and below) the specified nesting level")

args = parser.parse_args()

current_path = args.start_path
ascii_search = args.ascii
ascii_border = args.ab
entropy_border = args.eb
block_size = args.block
mode = args.mode
# nest_level = args.nest
bin_walk = args.binwalk

print("Going to start search from '" + current_path + "'")

# записывает путь к файлу в указанный файл

def store_result(file_path, out_file):
    out = open(out_file, "a")
    out.write(file_path + "\n")
    out.close()


# информационная энтропия (Шеннона)

def shannon_entropy(data):
    values_count = [0] * 256
    data_len = len(data)
    result = 0.0

    # считаем общее количество различных значений и количество каждого из значений для расчета вероятности 

    for byte in data:
        if values_count[byte] == 0:
            data_len += 1
        values_count[byte] += 1 
    
    # рассчитываем само значение энтропии

    for count in values_count:
        if count > 0:
            p = float(count) / data_len
            result += (p) * math.log2(p)

    return result * (-1)


# считает информационную энтропию для файла

def entropy_count(file_path):
    investigation_file = open(file_path, "rb")
    byte_array = investigation_file.read()
    investigation_file.close()

    return shannon_entropy(byte_array)


# считает процент содержания в файле читаемых ascii символов

def ascii_count(file_path):
    ascii_count = 0
    investigation_file = open(file_path, "rb")
                        
    data = investigation_file.read()
    investigation_file.close()

    for byte in data:
        if 32 <= byte <= 126:
            ascii_count += 1
                        
    investigation_file.close()
    return ascii_count / os.stat(file_path).st_size


# сохраняет mime type, процент ascii текста и энтропию в специальный файл

def store_all_info(file_path):
    mime = magic.from_file(file_path, mime=True)
    ascii_percentage = ascii_count(file_path)
    entropy = entropy_count(file_path)
    store_result(file_path + "\t" + mime + "\t" + str(ascii_percentage) + "\t" + str(entropy), ALL_STAT_FILE)



def store_all_info_b(file_path):
    mime = magic.from_file(file_path, mime=True)
    investigation_file = open(file_path, "rb")
    data = investigation_file.read()
    investigation_file.close()

    ascii_count = 0
    ascii_percentage = 0.0
    entropy = 0.0
    current_block_size = 0
    low_border = 0
    block_count = 0

    for i in range(len(data)):
        if i > 0 and i % block_size == 0 or i == len(data):
            ascii_percentage = ascii_count / current_block_size
            high_border = low_border + current_block_size
            data_peace = data[low_border:high_border]
            entropy = shannon_entropy(data_peace)

            store_result(file_path + ": block " + str(block_count) + "\t" + mime + "\t" + str(ascii_percentage) + "\t" + str(entropy), ALL_STAT_FILE)

            ascii_count = 0
            ascii_percentage = 0.0
            entropy = 0.0
            current_block_size = 0
            low_border = high_border
            block_count += 1

        if 32 <= data[i] <= 126:
            ascii_count += 1

        current_block_size += 1

# гуляет по директориям и проверяет файлы

def search_crypto(path, nest_lvl):

    if os.access(path, os.R_OK):
        print("Have access to folder '" + path + "'")

        for root, dirs, files in os.walk(path):

            # проверяем файлы в директории
            
            for file in files:  
                file_path = os.path.join(root, file)

                if os.access(file_path, os.R_OK):

                    print(file_path)

                    # это на будущее
                    # проверяем binwalk'ом на наличие сигнатур файлов
                    
                    if bin_walk:
                        modules = binwalk.scan(file_path, signature=True, quiet=True)
                        for module in modules:
                            if len(module.results) > 0:

                                out = open(BINWALK_FILE, "a")
                                out.write("%s Results:\n" % module.name)

                                for result in module.results:
                                    out.write("\t%s    0x%.8X    %s\n" % (result.file.path, result.offset, result.description))

                                out.close()

                    # разбиваем файл на блок и анализируем каждый блок

                    if block_size != None:
                        store_all_info_b(file_path)
                        continue

                    # получаем mime type файла

                    mime = magic.from_file(file_path, mime=True)

                    # всю информацию записываем в специальный файл

                    if mode == 'everything':
                        ascii_percentage = ascii_count(file_path)
                        entropy = entropy_count(file_path)

                        if ascii_percentage >= ascii_border and entropy >= entropy_border:
                            store_result(file_path + "\t" + mime + "\t" + str(ascii_percentage) + "\t" + str(entropy), ALL_STAT_FILE)

                        continue


                    # считаем процент содержания в файле читаемых ascii символов

                    if ascii_search:
                        ascii_percentage = ascii_count(file_path)
                        
                        if ascii_percentage >= ascii_border:
                            store_result(file_path + "\t" + str(ascii_percentage), ASCII_PERCENTAGE_FILE)


                    if mime != UNDEFINED_TYPE:
                        # это известный тип файла
                        # проверяем, является ли этот файл архивным

                        if mime in ARCHIVE_TYPES:
                            # print(file_path + " ==> " + magic.from_file(file_path, mime=True))

                            if mime == "application/zip":
                                # проверяем, запоролен ли этот архив
                                zf = zipfile.ZipFile(file_path)

                                for zinfo in zf.infolist():
                                    is_encrypted = zinfo.flag_bits & 0x1 

                                    if is_encrypted:
                                        store_result(file_path ,PAROLLED_ARCHIVE_FILE)
                                        
                                        if mode == "hybrid":
                                            store_all_info(file_path)
                                        break

                            if mime == "application/x-rar":
                                # проверяем, запоролен ли этот архив
                                rf = rarfile.RarFile(file_path)

                                for rinfo in rf.infolist():
                                    is_encrypted = rinfo.needs_password()

                                    if is_encrypted:
                                        store_result(file_path, PAROLLED_ARCHIVE_FILE)

                                        if mode == "hybrid":
                                            store_all_info(file_path)
                                        break
                            
                            if mime == "application/x-7z-compressed":
                                # проверяем, запоролен ли этот архив
                                z7f = py7zr.SevenZipFile(file_path)

                                if z7f.needs_password():
                                    store_result(file_path, PAROLLED_ARCHIVE_FILE)

                                    if mode == "hybrid":
                                        store_all_info(file_path)

                            store_result(file_path, ARCHIVE_FILE)

                        # если не архивный - проверяем, запароленный ли это документ

                        else:

                            if mime == PAROLLED_DOCUMENT_MIME:
                                store_result(file_path, PAROLLED_DOCUMENT_FILE)

                                if mode == "hybrid":
                                    store_all_info(file_path)
                            
                            elif mime == PDF_DOCUMENT_MIME:
                                pdfFileObj = open(file_path, 'rb')
                                pdfReader = PyPDF2.PdfFileReader(pdfFileObj)

                                if pdfReader.isEncrypted:
                                    store_result(file_path, PAROLLED_DOCUMENT_FILE)

                                    if mode == "hybrid":
                                        store_all_info(file_path)

                    else:
                        # высчитываем энтропию Шеннона
                        # если больше 7 => архивный или зашифрованный файл

                        entropy = entropy_count(file_path)

                        if mode == "auto":
                            if entropy >= entropy_border:
                                store_result(file_path, ENCRYPTED_FILE)
                        else:
                            store_all_info(file_path)

                    # проверяем уровень вложенности

                    # if nest_lvl >= nest_level:
                    #     out = open(NEST_FILE, "a")
                    #     out.write(file_path + "\n")
                    #     out.close()
                    
        
                else:
                    print("No permission to open file '" + file_path + "'")
                    store_result(file_path + " ACCESS DENIED", ERROR_FILE)

            for dir in dirs:
                # рекурсивно отправляемся в поддиректории

                dir_path = os.path.join(root, dir)
                search_crypto(dir_path, nest_lvl + 1)

            return    
    else:
        print("No permission to open folder '" + path + "'") 
        store_result(path + " ACCESS DENIED", ERROR_FILE)   


# clear output files

def init_work():
    open(ARCHIVE_FILE, "w").close()
    open(PAROLLED_ARCHIVE_FILE, "w").close()
    open(PAROLLED_DOCUMENT_FILE, "w").close()
    open(ENCRYPTED_FILE, "w").close()
    open(ASCII_PERCENTAGE_FILE, "w").close()
    open(ALL_STAT_FILE, "w").close()
    open(ERROR_FILE, "w").close()
    open(NEST_FILE, "w").close()
    open(BINWALK_FILE, "w").close()


# главный цикл

init_work()

if os.access(current_path, os.F_OK):
    print("Scanning ...")
    search_crypto(current_path, 0)
    print("... work is done")
else:
    print("Directory '" + current_path + "' does not exist")
    store_result(current_path + " ACCESS DENIED", ERROR_FILE) 
# This is the main Karken Project.
from flask import Flask, render_template, request, redirect, send_file
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
from wtforms.validators import InputRequired
from werkzeug.datastructures import FileStorage
import os, filetype, hashlib, pathlib
from fpdf import FPDF
# Flask importing Libaryes Done now moving on to malware libraries.
from capstone import * # The Dissamble
import vt , pefile, yara , rzpipe # VirusTotall libarry API, pefile libary, yara , rzpipe
app = Flask(__name__)
app.config['SECRET_KEY'] = 'JAXTestingKey'
app.config['UPLOAD_FOLDER'] = 'static/files'
class UploadFileForm(FlaskForm):
    file = FileField('file', validators=[InputRequired()])
    submit = SubmitField('submit')
@app.route('/')

def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])

def upload():
    form = UploadFileForm()
    if form.validate_on_submit():
        global file 
        file = form.file.data 
        filetype = file.filename.split('.')[1]
        if filetype == "exe":
            file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'],secure_filename(file.filename)))
            global filepath
            filepath = file.filename.split('(')[0]
            global removing
            removing = pathlib.Path(f"static/files/{filepath}")
            return redirect('upload/analysis')
        else:
            return "Sorry only exe are allowed"
    return render_template('upload.html', form=form)
    
@app.route("/upload/analysis", methods=['GET', 'POST'])

def analysis():
    md5 = hashlib.md5(open(f"static/files/{filepath}", "rb").read()).hexdigest()
    client = vt.Client("<VT - API key here >")
    malware = client.get_object(f"/files/{md5}")
    get_file_size = malware.size
    file_size = f"File size is : {get_file_size}"
    get_file_tag = malware.type_tag
    file_tag = f"File tag is : {get_file_tag}"
    get_the_stats = malware.last_analysis_stats
    file_status = f"File status is : {get_the_stats}"
    get_sha256 = malware.sha256
    file_sha = f"File sha256 : {get_sha256}"
    get_first_sub = malware.first_submission_date
    file_first_sub = f"File first submission : {get_first_sub} "
    get_total_vote = malware.total_votes
    file_total_vote = f"File total votes : {get_total_vote}"
    time_sub = malware.times_submitted
    file_times_sub = f"File times submitted : {time_sub}"
    get_sumaliar_files = malware.vhash
    file_sum = f"Hash of files share sumaliar hashs : {get_sumaliar_files}"
    virustotall = FPDF() # Save fpdf calss into virable/
    virustotall.add_page() # add a Page 
    virustotall.set_font("Arial", size= 8) # Set the Size and the font of it
    virustotall.set_text_color(255, 0, 0)
    virustotall.rect(0, 0, 1000, 1000, style="F")
    talk_1 = """
    What is VirusTotal ? :  VirusTotal is an Alphabet product that analyzes suspicious files,
    URLs, domains and IP addresses to detect malware and other types of threats,
    and automatically shares them with the security community."""
    virustotall.cell(w=700, h=7, txt="-----------------------------------------------------------------------------------------------------------------------------------------", ln=1)
    virustotall.multi_cell(w= 300, h= 5, txt= talk_1)
    virustotall.cell(w=700, h=7, txt="-----------------------------------------------------------------------------------------------------------------------------------------", ln=2)
    virustotall.cell(w=20, h=7, txt= "# Output : ", ln=1)
    virustotall.cell(w=30, h=11, txt= file_size, ln=1)
    virustotall.cell(w=30, h=11, txt= file_tag, ln=1)
    virustotall.cell(w=700, h=11, txt= file_status, ln=1)
    virustotall.cell(w=30, h=11, txt= file_sha, ln=1)
    virustotall.cell(w=30, h=11, txt= file_first_sub, ln=1)
    virustotall.cell(w=30, h=11, txt= file_total_vote, ln=1)
    virustotall.cell(w=30, h=11, txt= file_times_sub, ln=1, )
    virustotall.cell(w=30, h=11, txt= file_sum)
    virustotall.output('static/pdf/VirusTotal.pdf')
    # Now Moving to PEfile
    exefile = f"static/files/{filepath}"
    exe = pefile.PE(exefile)
    pefile_pdf = FPDF()
    pefile_pdf.add_page()
    pefile_pdf.set_font("Arial", size=7)
    pefile_pdf.set_text_color(255, 0, 0)
    pefile_pdf.rect(0, 0, 1000, 1000, style="F")
    talk_2 = """
    PEfile is a library used to parse the Portable Executable format. It is very useful for malware
    analysis as it allows to extract information about the file such as Import Table,
    headers information and more. It also has some packer detection mechanisms with PEiD signature embedded."""
    pefile_pdf.cell(w=700, h=7, txt="-----------------------------------------------------------------------------------------------------------------------------------------", ln=1)
    pefile_pdf.multi_cell(w=300, h=5 , txt= talk_2 )
    pefile_pdf.cell(w=700, h=7, txt="-----------------------------------------------------------------------------------------------------------------------------------------", ln=1)
    pefile_pdf.cell(w=20, h=7, txt= "# Output : ")
    pefile_pdf.multi_cell(w=3000, h=7, txt= f"{exe}")
    pefile_pdf.output("static/pdf/pefile.pdf")
    # Now Moving to Capston.
    talk_3 = """
    Capstone Engine is a framework for binary disassembly.
    a powerful library that allows to disassemble binaries.
    It is particularly useful if you want to automate some
    of your reverse engineering analysis or identify known
    pattern for evasion techniques."""
    capston = FPDF()
    capston.add_page()
    capston.set_font("Arial", size= 8)
    capston.set_text_color(255, 0, 0)
    capston.rect(0, 0, 3000, 3000, style="F")
    capston.multi_cell(w= 450, h= 5 , txt= talk_3)
    Entry_Point = exe.OPTIONAL_HEADER.AddressOfEntryPoint
    Data = exe.get_memory_mapped_image()[Entry_Point:]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    Rdbin = cs.disasm(Data, 0x1000)
    for i in Rdbin:
        value= "%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
        capston.cell(w=20, h=7, txt= "# Output :")
        capston.multi_cell(w= 600, h= 5, txt= value)
    capston.output("static/pdf/capstone.pdf")
    # Now moving to yara
    talk_4 = """
        What is Yara ? : Yara is one of the most used tools for malware research,
        it is used to create signature detection and very useful for malware hunting.
        The python library allows using Yara in your scripts with your own set of rules."""
    yara_pdf = FPDF()
    yara_pdf.add_page()
    yara_pdf.set_font("Arial", size= 5)
    yara_pdf.set_text_color(255, 0, 0)
    yara_pdf.rect(0, 0, 1000, 1000, style="F")
    rule = yara.compile("yara/shellcode-windows-x64-stager_reverse_tcp_nx.asm.yar")
    matches = rule.match(exefile)
    if matches:
        yara_pdf.multi_cell(w= 450, h=3 , txt = talk_4)
        yara_pdf.cell(w= 20, h=5, txt= "# Output : [Note ! : The detection for metasploit staged malware only ! ]", ln=1)
        yara_pdf.multi_cell(w= 250, h= 5, txt= f"{matches}")
    else:
        yara_pdf.multi_cell(w= 450, h=3 , txt = talk_4)
        yara_pdf.cell(w= 20, h=5, txt= "# Output : # Output : [Note ! : The detection for metasploit staged malware only ! ]", ln=1)
        yara_pdf.cell(w = 20, h=5 , txt = "No malware Detected !")
    yara_pdf.output("static/pdf/yara.pdf")
    # Now Moving to the last part (rzpipe) . 
    pipe = rzpipe.open(exefile)
    pipe.cmd("aaa")
    i_function = pipe.cmd("i") # Show info of current file
    i_function_2 = pipe.cmd("ia") # Show a summary of all info (imports, exports, sections, etc.)
    i_function_3 = pipe.cmd("ih") # Show binary fields
    i_function_4 = pipe.cmd("iH") # Show binary headers
    i_function_5 = pipe.cmd("it") # Show file hashes
    talk_5 = """
    Rz-pipe, is a python wrapper for Rizin an open-source disassembler which replaces Radare2.
    The wrapper allows to use the usual commands in python which is very handy for automation and analysis."""
    rzpipe_pdf = FPDF()
    rzpipe_pdf.add_page()
    rzpipe_pdf.set_font("Arial", size= 8)
    rzpipe_pdf.set_text_color(255, 0, 0)
    rzpipe_pdf.rect(0, 0, 5000, 5000, style="F")
    rzpipe_pdf.multi_cell(w= 500, h = 7, txt= talk_5)
    rzpipe_pdf.cell(w=20, h=7, txt= "Info of the current file : ", ln=1)
    rzpipe_pdf.multi_cell(w= 700, h= 7, txt= f"{i_function}")
    rzpipe_pdf.cell(w=20, h=7, txt= "Summary of all info imports, exports, sections, etc. : ", ln=1)
    rzpipe_pdf.multi_cell(w= 700, h= 7, txt=f"{i_function_2}")
    rzpipe_pdf.cell(w=20, h=7, txt= "Binary fields : ", ln=1)
    rzpipe_pdf.multi_cell(w= 700, h= 7, txt= f"{i_function_3}")
    rzpipe_pdf.cell(w=20, h=7, txt= "Binary headers : ", ln=1)
    rzpipe_pdf.multi_cell(w= 700, h= 7 , txt= f"{i_function_4}")
    rzpipe_pdf.cell(w=20, h=7, txt= "file hashes : ", ln=1)
    rzpipe_pdf.multi_cell(w= 700, h= 7, txt= f"{i_function_5}")
    rzpipe_pdf.output("static/pdf/rzpipe.pdf")
    removing.unlink()
    # Finish.
    return render_template("analysis.html")
    


# Serving PDF Files
@app.route("/pdf/1")
def Virustotall():
    return send_file("static/pdf/VirusTotal.pdf")

@app.route("/pdf/2")
def PEFILE():
    return send_file("static/pdf/pefile.pdf")

@app.route("/pdf/3")
def capstone():
    return send_file("static/pdf/capstone.pdf")

@app.route("/pdf/4")
def yara_output():
    return send_file("static/pdf/yara.pdf")


@app.route("/pdf/5")
def rzpipe_output():
    return send_file("static/pdf/rzpipe.pdf")



app.run(host="0.0.0.0", port=8080)

FROM python:3
RUN echo 'deb http://download.opensuse.org/repositories/home:/RizinOrg/Debian_11/ /' | tee /etc/apt/sources.list.d/home:RizinOrg.list
RUN curl -fsSL https://download.opensuse.org/repositories/home:RizinOrg/Debian_Testing/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/home_RizinOrg.gpg > /dev/null
RUN apt update && apt install -y libcapstone-dev rizin
RUN python -m pip install --upgrade pip
ENV DEBIAN_FRONTEND=noninteractive
RUN pip install flask flask_wtf wtforms Werkzeug wtforms_validators filetype  pathlib fpdf capstone vt-py pefile yara rzpipe
RUN mkdir /opt/kraken
WORKDIR /opt/kraken
COPY . .
RUN ln -s /usr/local/lib/python3.11/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
CMD [ "python", "/opt/kraken/Kraken.py" ]
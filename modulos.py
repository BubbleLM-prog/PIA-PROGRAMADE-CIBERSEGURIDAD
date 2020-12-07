import argparse
import socket
import sys
from datetime import datetime
import logging
from bs4 import BeautifulSoup
import requests
from lxml import html
import email, smtplib, ssl
import mimetypes
import subprocess
import os
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import errno
FROM library/python:2.7-slim

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY get_status.py .
RUN chmod a+x get_status.py

ENTRYPOINT [ "./get_status.py" ]



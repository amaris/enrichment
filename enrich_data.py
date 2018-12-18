import pymongo
import requests
import yaml
import datetime
import logging
import os
import ast
from threading import Thread, Lock
from bottle import Bottle, run
import signal
import sys
import time
import copy
import argparse

# variables for stats
updated_docs, not_updated_docs, error_docs, error_insertion = [0] * 4
# stop process variable
to_stop = False
#lock to ontrol access to variables
data_lock = Lock()
#threading handler
update_thread = Thread()


def call_api(conf, txt):
    api_conf = conf["API"]
    if api_conf["port"]:
        url = '%s:%d%s' % (api_conf["hostname"], api_conf["port"], api_conf["path"])
    else:
        url = '%s%s' % (api_conf["hostname"], api_conf["path"])
    try:
        if txt:
            # build data to be passed in the body
            payload = copy.deepcopy(api_conf["parameters"])
            for key in payload.keys():
                if payload[key] == "inputField":
                    payload[key] = txt
                    break
            if api_conf["httpMethod"] == "POST":
                res = requests.post(url, json=payload)
                data = res.json()
                return url, data
            elif api_conf["httpMethod"] == "GET":
                res = requests.get(url, params=payload)
                data = res.json()
                return url, data
        else:
            return url, None
    except ValueError:
        return url, None


def update_document(conf, document):
    input_field = conf["InfoInjection"]["input"]["inputField"]
    try:
        text = document[input_field]
    except KeyError:
        logger.info("No text file for doc %s" % document["_id"])
    else:
        url, api_result = call_api(conf, text)
        if api_result:
            return url, api_result
        else:
            logger.info("API call NOK for %s" % document["_id"])
            return url, None


def check_update_viability(key_to_inject, doc, update_interval):
    if "Enrichments" in doc.keys():
        metadata = doc["Enrichments"]
        if key_to_inject not in metadata.keys():
            # the info doesn't exist in the doc
            return True
        else:
            update_date = metadata[key_to_inject]["Timestamp"]
            if (datetime.datetime.utcnow() - update_date).days >= update_interval:
                # info should be updated
                return True
        return False
    else:
        return True


def mongo_iterator(conf, cursor):
        info_to_inject = conf["InfoInjection"]["keyToAdd"]
        update_interval = conf["InfoInjection"]["UpdatePeriodInDays"]
        batch_size = int(conf["InfoInjection"]["batchSize"])
        # build the aggregate pipeline
        try:
            pipeline = ast.literal_eval(conf["InfoInjection"]["input"]["inputMongoPipeline"])
        except SyntaxError:
            logger.error("The pipeline given couldn't be parsed")
            raise
        for p_element in pipeline:
            if "$project" in p_element.keys():
                p_element["$project"][info_to_inject] = 1
                p_element["$project"]["Enrichments"] = 1
        # test pipeline in mongo
        try:
            pipeline.append({"$limit": 2})
            pipeline.append({"$skip": 1})
            cursor.aggregate(pipeline)
            del pipeline[-2:]
        except pymongo.errors.OperationFailure as e:
            logger.error(e.details["errmsg"])
            raise

        #pipeline = [{"$project": {"_id": 1, "Content": {"$arrayElemAt": ["$Contents", 0]}, info_to_inject: 1}}]
        done = False
        while not done:
            try:
                for current_doc in cursor.aggregate(pipeline).batch_size(batch_size):
                    # check if main thread was not stopped
                    if check_continue():
                        global data_lock
                        with data_lock:
                            try:
                                # check if the document hasn't already the information
                                if check_update_viability(info_to_inject, current_doc, update_interval):
                                    url, api_result = update_document(conf, current_doc)
                                    # insert sub_doc in mongo document
                                    info_metadata_path = "Enrichments.%s" % info_to_inject
                                    metadata = {"Label": info_to_inject, "Timestamp": datetime.datetime.utcnow(),
                                                "Source": url}
                                    if api_result:
                                        metadata["Status"] = "OK"
                                        cursor.update_one({"_id": current_doc["_id"]},
                                                          {'$set': {info_to_inject: api_result,
                                                                    info_metadata_path: metadata}})
                                    else:
                                        metadata["Status"] = "Error"
                                        cursor.update_one({"_id": current_doc["_id"]},
                                                          {'$set': {info_metadata_path: metadata}})

                                    if metadata["Status"] == "OK":
                                        global updated_docs
                                        updated_docs += 1
                                    else:
                                        global error_insertion
                                        error_insertion += 1
                                else:
                                    # doc was not updated
                                    global not_updated_docs
                                    not_updated_docs += 1
                            except Exception as e:
                                global error_docs
                                error_docs += 1
                                logger.error("Error processing doc %s" % current_doc["_id"])
                    else:
                        break
                done = True
                logger.info("Information injection ended successfully")
            except pymongo.errors.OperationFailure as e:
                msg = e.details["errmsg"]
                if not(msg.startswith("cursor id") or msg.startswith("Cursor not found")):
                    logger.error(e)
                    raise
        logger.info("Documents updated : %d" % updated_docs)
        logger.info("Documents updated with error: %d" % error_insertion)
        logger.info("Documents not updated: %d" % not_updated_docs)
        logger.info("Documents with unexpected error: %d" % error_docs)
        while check_continue():
            continue


def check_continue():
    global to_stop
    global data_lock
    with data_lock:
        return not to_stop


def interrupt(signal, frame):
    global to_stop
    global data_lock
    with data_lock:
        to_stop = True
    time.sleep(3)
    print("Process ended successfully with signal " + str(signal))
    sys.exit(0)

if __name__ == "__main__":
    # read config file
    parser = argparse.ArgumentParser(description="Conf for data enrichment")
    parser.add_argument('--conf', required=False, default="conf_for_enrichment.yml")
    args = vars(parser.parse_args())
    conf_path = os.path.join("conf", args["conf"])
    conf = yaml.load(open(conf_path))
    host = conf["mongodb"]["hostname"]
    port = conf["mongodb"]["port"]
    usr = conf["mongodb"]["user"]
    pwd = conf["mongodb"]["password"]
    auth_source = conf["mongodb"]["authSource"]
    # create logger
    report_folder = os.path.join("var", "log", "enrichment", "reports")
    file_name = "%s_%s.txt" % (conf["API"]["name"], datetime.datetime.now().strftime("%Y-%m-%d"))
    LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
    logging.basicConfig(filename=os.path.join(report_folder, file_name), level= logging.INFO, format=LOG_FORMAT)
    logger = logging.getLogger()
    try:
        # create the mongo client
        if not usr and not pwd:
            # used for local access
            client = pymongo.MongoClient("mongodb://%s:%d/%s" % (host, port, auth_source))
        else:
            client = pymongo.MongoClient("mongodb://%s:%s@%s:%d/%s" % (usr, pwd, host, port, auth_source))
        db = client[conf["mongodb"]["db"]]
        col = db[conf["mongodb"]["col"]]
    except:
        logger.info("Could not connect to Mongo")

    try:
        thread = Thread(target=mongo_iterator, args=(conf, col))
        thread.start()
    except Exception as e:
        logger.error("Not possible to launch the thread")
    else:
        app = Bottle()

        @app.route('/Enrichment/status', method="GET")
        def enrichment_status():
            with data_lock:
                return {'Updated': updated_docs, 'Updated with error': error_insertion, 'Not Updated': not_updated_docs,
                        'Unexpected Errors': error_docs}

        signal.signal(signal.SIGINT, interrupt)
        run(app, host='0.0.0.0', port=conf["port"])

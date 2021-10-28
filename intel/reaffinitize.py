from . import k8s
from . import reconfigure
from kubernetes.client.rest import ApiException as K8sApiException
import logging
import psutil
import sys
import yaml


def reaffinitize(node_name, namespace):
    configmap_name = "cmk-reconfigure-{}".format(node_name)
    procs = get_config_from_configmap(configmap_name, namespace)
    reaffinitize_cores(procs)

'''def foo_constructor(loader, node):
    values = loader.construct_mapping(node)
    process_map = values["process_map"]
    logging.debug("process_map: {}".format(process_map))
    procs = reconfigure.Procs()
    return procs
'''
def parse_pid_line(input_line):
    parts = input_line.split("!!")
    str1 = parts[0].strip()
    str2 = parts[1].strip()
    match_str = "python/object:intel.reconfigure.Pid"
    if str2 != match_str:
        logging.debug("ERROR: invalid line: \"{}\" (valid should end with: \"{}\")".format(input_line, match_str))
        return None
    parts = str1.split("'")
    pid = parts[1] # string "'30030':" to be split("'") will get parts: ['', '30030', ':']
    return pid

def parse_new_clist_line(input_line):
    parts = input_line.split(":")
    str1 = parts[0].strip()
    str2 = parts[1].strip()
    match_str = "new_clist"
    if str1 != match_str:
        logging.debug("ERROR: invalid line: \"{}\" (valid should start with: \"{}\")".format(input_line, match_str))
        return None
    return str2

def parse_reconfigure_info(config_data):
    lines = config_data.splitlines()
    match_str = "!!python/object:intel.reconfigure.Procs"
    if lines[0] != match_str:
        logging.debug("ERROR: invalid line: \"{}\" (valid should end with: \"{}\")".format(lines[0], match_str))
        return None
    match_str = "process_map:"
    if lines[1] != match_str:
        logging.debug("ERROR: invalid line: \"{}\" (valid should start with: \"{}\")".format(lines[1], match_str))
        return None

    procs = reconfigure.Procs()
    idx = 2
    while idx < len(lines):
        #get pid
        line = lines[idx]
        pid = parse_pid_line(line)

        #get new_clist
        idx += 1
        line = lines[idx]
        new_clist = parse_new_clist_line(line)

        #get old_clists, and add to the procs object
        idx += 1
        line = lines[idx]
        match_str = "old_clists:"
        if line.strip() != match_str:
            logging.debug("ERROR: invalid line: \"{}\" (valid should be: \"{}\")".format(line, match_str))
            return None

        idx += 1
        line = lines[idx].strip()
        if line[0:2] != "- ":
            logging.debug("ERROR: invalid line: \"{}\" (valid should begin with \"- \")".format(line))
            return None
        old_clist = line[2:]
        procs.add_proc(pid, old_clist)

        #add new_clist to the procs object
        procs.process_map[pid].add_new_clist(new_clist)

        idx += 1

    logging.debug("INFO: parse_reconfigure_info() produces procs: {}".format(yaml.dump(procs)))
    return procs


def get_config_from_configmap(name, namespace):
    try:
        config = k8s.get_config_map(None, name, namespace)
        logging.debug("yi-raf-1: config.data[\"config\"]) = \n{}".format(config.data["config"]))
        #yaml.add_constructor(u'!intel.reconfigure.Procs', foo_constructor)
        #config = yaml.safe_load(config.data["config"])#TODO fix: the code before fix is config["config"], but yaml.safe_load() didn't throw exception, such that reconfigure() would not detects this failure, so the result of reconfigure() was configmap updated but core re-affinitizing unchanged
        logging.debug("config.data[\"config\"] is of type: {}".format(type(config.data["config"])))
        config = parse_reconfigure_info(config.data["config"])
    except K8sApiException as err:
        logging.error("Error while retreiving configmap {}".format(name))
        logging.error(err.reason)
        sys.exit(1)
    return config


def reaffinitize_cores(procs):
    # Reaffinitize works on the assumption that the process that are
    # running the pinned workloads are all children of the main
    # process in the pod. It takes the first process from the /procs
    # directory and works its way down each child process, reassigning
    # the process based on information in the procs parameter

    p = psutil.Process(1)
    while True:
        affin = p.cpu_affinity()
        affin_found = False
        for pid in list(procs.process_map.keys()):
            cl = ",".join(procs.process_map[pid].old_clists)
            correct_clist = [int(c) for c in cl.split(",")]
            #if set(correct_clist) == set(affin): #x-advisor: for fine-grain affinity config
            if set(affin).issubset(set(correct_clist)):
                new_affin = [int(c) for c in
                             procs.process_map[pid].new_clist.split(",")]
                logging.info("New core alignment: {}"
                             .format(new_affin))
                affin_found = True
                p.cpu_affinity(new_affin)
                break

        if not affin_found:
            # If the process's affinity doesn't match any of the
            # ones in core_alignment we can just ignore it and
            # move onto its child process.

            logging.info("No affinity found, leaving as old value {}"
                         .format(affin))

        try:
            p = p.children()[0]
        except IndexError:
            break

def reaffinitize_process_cores(pid, new_affin):
    p = psutil.Process(pid)
    affin = p.cpu_affinity()
    p.cpu_affinity(new_affin)
    print("Process {} core affinity change: from {} to {}".format(pid, affin, new_affin))
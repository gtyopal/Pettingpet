import logging
import urllib

from chalice import Chalice, CORSConfig, IAMAuthorizer
from chalice import Rate
from chalice import UnauthorizedError
from chalice import ChaliceViewError
from chalice import ForbiddenError
from chalice import BadRequestError

from chalicelib.acs_backend.activity import *
from chalicelib.acs_backend.activity.collection import CollectionActivity
from chalicelib.acs_backend.type import QASample, Organization
from chalicelib.acs_backend.type.auth_type import AuthType
from chalicelib.acs_backend.util.scenarios_yaml_utils import update_scenarios, validate_scenarios
from chalicelib.acs_backend.util.template_permission import TemplatePermission
from chalicelib.bot_benchmark.activity import *

from chalicelib.acs_backend.exception import *

from chalicelib.acs_backend.util import MTurkHelper, AuthUtils
from chalicelib.acs_backend.util.metrics import Metrics, MetricsHelper
from chalicelib.acs_backend.util.logging_utils import init_logging

import json
import os
import time
import traceback
import random
import hashlib

import cgi
from io import BytesIO

from chalicelib.bot_benchmark.util import ser_dict_dates

app = Chalice(app_name='acs-backend')
app.debug = True
init_logging(app)
MetricsHelper.init(app)

iam_authorizer = IAMAuthorizer()

# CORS configuration for relevant endpoints
cors_config = CORSConfig(allow_headers=['token'])


def __handle_exception(exception):
    logging.error('General Handle Exception: {}'.format(exception))
    if type(exception) == UserInputError:
        raise BadRequestError(str(exception))
    elif type(exception) == AuthorizationError:
        raise UnauthorizedError(str(exception))
    elif type(exception) == PermissionsError:
        raise ForbiddenError(str(exception))
    elif type(exception) == DependencyError:
        traceback.print_exc()
        raise ChaliceViewError(str(exception))
    elif isinstance(exception, ChaliceViewError):
        traceback.print_exc()
        raise exception
    else:
        traceback.print_exc()
        raise ChaliceViewError('Uncaught exception: ' + str(exception))


# ============== Conversations ==============

@app.route('/conversation', methods=['POST'], cors=True)
def create_conversation():
    request_body = app.current_request.json_body
    app.log.info("Got request to create conversation, input: {}".format(request_body))

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = ConversationActivity.create_conversation_for_agent(
            agent=requesting_agent,
            template_id=request_body['template_id'] if 'template_id' in request_body and len(request_body['template_id']) else None)
        app.log.info("Succeeded to create conversation, result: {}".format(activity_result))
    except Exception as e:
        __handle_exception(e)

    return {
        'template_id': activity_result['template_id'],
        'agentURL': activity_result['agentURL'],
        'customerURL': activity_result['customerURL'],
        'hit_id': activity_result['hit_id']
    }

@app.route('/hint/{id}', methods=['GET'], cors=cors_config)
def get_hint(id):
    try:
        # See if an optional logged in agent token exists on this request
        requesting_agent = None
        request_headers = app.current_request.headers
        app.log.info("Got request to get hint, id={}".format(id))
        if 'token' in request_headers:
            try:
                requesting_agent = AgentActivity.get_agent_from_token(request_headers['token'])
            except Exception as e:
                app.log.warning("Token could not resolve to agent, caught an exception: {}", e, exc_info=True)

        conversation_data = ConversationActivity.get_conversation(conversation_id=id, requesting_agent=requesting_agent)

        template_id = conversation_data['template_id']
        template_data = CollectionTemplateActivity.get_full_template(template_id)
        app.log.info("Got full template for template_id={}, result={}".format(template_id, template_data))

        hint_data = ConversationActivity.get_conversation_hints(conversation_data, template_data)
        return {
            'slot_name': hint_data.get("slot_name", None),
            'hint_message': hint_data.get("hint_message", None)
        }

    except Exception as e:
        __handle_exception(e)

@app.route('/conversation/{id}', methods=['GET'], cors=cors_config)
def get_conversation(id):
    try:
        # See if an optional logged in agent token exists on this request
        requesting_agent = None
        request_headers = app.current_request.headers
        app.log.info("Got request to get conversation, id={}".format(id))
        if 'token' in request_headers:
            try:
                requesting_agent = AgentActivity.get_agent_from_token(request_headers['token'])
            except Exception as e:
                app.log.warning("Token could not resolve to agent, caught an exception: {}", e, exc_info=True)

        activity_result = ConversationActivity.get_conversation(conversation_id=id, requesting_agent=requesting_agent)
        app.log.info("Fetched conversation with id {} : {}".format(id, activity_result))
    except Exception as e:
        __handle_exception(e)

    return {
        'authors': activity_result['authors'],
        'statements': activity_result['statements'],
        'template_id': activity_result['template_id'],
        'closed': activity_result['closed'],
        'successful': activity_result['successful'],
        'conversation_id': activity_result['conversation_id'],
        'last_updated': activity_result['last_updated']
    }


@app.route('/conversation/full/{id}', methods=['GET'] , authorizer=iam_authorizer)
def get_full_conversation(id):
    try:
        activity_result = ConversationActivity.get_full_conversation(conversation_id=id, requesting_agent=None,
                                                                     auth_type=AuthType.IAM_AUTH)
        app.log.info("Fetched conversation with id {} : {}".format(id, activity_result))
    except Exception as e:
        __handle_exception(e)

    return activity_result


@app.route('/conversation/{id}', methods=['POST'], cors=cors_config)
def update_conversation(id):
    request_body = app.current_request.json_body

    if 'author' not in request_body or 'author_id' not in request_body['author'] or 'author_key' not in request_body['author']:
        raise BadRequestError('\'author\' parameter not supplied or invalid!')
    if 'content' not in request_body:
        raise BadRequestError('\'content\' parameter not supplied or invalid!')
    if 'payload' not in request_body:
        request_body['payload'] = None  # Payload is optional, stub to None if not provided for consistency and legacy support

    try:
        app.log.info("Got request to update conversation, id={}, agent={}, content={}, payload={}".format(
            id, request_body['author'], request_body['content'], request_body['payload']))
        ConversationActivity.update_conversation(id, request_body['author'], request_body['content'],
                                                 request_body['payload'])
        app.log.info("Successfully updated conversation with id {}".format(id))
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/conversation/{id}/annotation/{turn_id}', methods=['POST'], cors=cors_config)
def update_annotation_for_conversation(id, turn_id):
    request_body = app.current_request.json_body

    if 'author' not in request_body or 'author_id' not in request_body['author'] or 'author_key' not in request_body['author']:
        raise BadRequestError('\'author\' parameter not supplied or invalid!')
    if 'payload' not in request_body:
        raise BadRequestError('\'payload\' parameter not supplied or invalid!')

    try:
        ConversationActivity.update_annotation_for_conversation(id, turn_id, request_body['author'], request_body['payload'])
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/iam/conversation/{id}/utterance/{turn_id}', methods=['POST'], authorizer=iam_authorizer)
def update_utterance_for_conversation(id, turn_id):
    request_body = app.current_request.json_body

    if 'utterance_text' not in request_body:
        raise BadRequestError('\'utterance_text\' parameter not supplied or invalid!')

    try:
        app.log.info("Got request to update utterance for conversation, id={}, turn_id={}".format(id, turn_id))
        ConversationActivity.update_utterance_for_conversation(id, turn_id, request_body['utterance_text'])
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/conversation/{id}', methods=['PATCH'], cors=cors_config)
def patch_conversation(id):
    request_body = app.current_request.json_body

    if 'author' not in request_body or 'author_id' not in request_body['author'] or 'author_key' not in request_body['author']:
        raise BadRequestError('\'author\' parameter not supplied or invalid!')
    if 'task' not in request_body or 'hit_id' not in request_body['task'] or 'assignment_id' not in request_body['task'] or 'worker_id' not in request_body['task']:  # turk_submit_to is optional
        raise BadRequestError('\'task\' parameter not supplied or invalid!')

    try:
        app.log.info("Got request to patch conversation, id={}, agent={}, task={}".format(id, request_body['author'],
                                                                                          request_body['task']))
        ConversationActivity.attach_mturk_task_details_to_conversation(id, request_body['author'], request_body['task'])
        app.log.info("Successfully patched conversation with id {}".format(id))
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/conversation/{id}', methods=['DELETE'], cors=cors_config)
def close_conversation(id):
    request_body = app.current_request.json_body

    if 'author' not in request_body or 'author_id' not in request_body['author'] or 'author_key' not in request_body['author']:
        raise BadRequestError('\'author\' parameter not supplied or invalid!')
    if 'result' not in request_body or 'agent_rating' not in request_body['result']:
        raise BadRequestError('\'result\' parameter not supplied or invalid!')

    if 'notes' not in request_body['result'] or len(request_body['result']['notes']) == 0:
        request_body['result']['notes'] = None

    try:
        app.log.info("Got request to close conversation, id={}, agent={}, closing_param={}".format(
            id, request_body['author'], request_body['result']))
        ConversationActivity.close_conversation(id, request_body['author'], request_body['result'])
        app.log.info("Successfully closed conversation with id {}".format(id))
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/iam/conversation/{id}', methods=['DELETE'], authorizer=iam_authorizer)
def close_conversation_using_iam(id):
    """
    close_conversation_using_iam API is different from close_conversation API in below aspects:

    1. close_conversation_using_iam uses IAM Auth as explained by its name. close_conversation uses CCT provided auth.
    2. close_conversation_using_iam does not accept body as input. This was done because AWS Java SDK (along with
      underlying Apache HTTP Client) does not support body in DELETE API. Also, DELETE API accepting body is not norm
      and probably AWS Java SDK will not support it.
      Ideally we should expose another POST API to update closing params that can be called before DELETE API.

      TODO we should create another API named update_closing_params_for_conversation that should be called by CCT
        frontend before it calls close_conversation API. Then close_conversation and close_conversation_using_iam will
        become consistent.
    """
    try:
        app.log.info("Got request to close conversation, id={}".format(id))
        ConversationActivity.close_conversation(id, None, None, auth_type=AuthType.IAM_AUTH)
        app.log.info("Successfully closed conversation with id {}".format(id))
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/iam/conversation', methods=['POST'], authorizer=iam_authorizer)
def create_conversation_using_iam():
    request_body = app.current_request.json_body
    if 'conversation' not in request_body:
        raise BadRequestError('\'conversation\' parameter not supplied or invalid!')
    conversation_json = request_body['conversation']

    try:
        app.log.info("Got request to create conversation, id={}".format(conversation_json.get('conversation_id')))
        ConversationActivity.create_conversation(conversation_json, AuthType.IAM_AUTH)
        app.log.info("Successfully created conversation with id {}".format(conversation_json.get('conversation_id')))
        return {'successful': True}
    except Exception as e:
        __handle_exception(e)


# ============== Archive Access, Review, and Bundling ==============

@app.route('/conversation/archive/list/collection_reference/{collection_reference_id}', methods=['GET'], cors=cors_config)
def get_conversation_list_from_collection_reference(collection_reference_id):
    request_headers = app.current_request.headers
    if 'token' not in request_headers:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    try:
        app.log.info("Got request to list conversations with collection_reference_id={}".format(
            collection_reference_id))
        requesting_agent = AgentActivity.get_agent_from_token(request_headers['token'])

        # The ID's are often URLs and come in URI encoded
        collection_reference_id = urllib.unquote(collection_reference_id)
        activity_result = ConversationActivity.list_all_conversations_for_collection(
            agent=requesting_agent, collection_reference=collection_reference_id)

        app.log.info("Listed {} conversations: {}".format(len(activity_result['conversation_references']),
                                                          activity_result['conversation_references']))
    except Exception as e:
        __handle_exception(e)

    return {
        'collection_reference': collection_reference_id,
        'conversation_references': activity_result['conversation_references']
    }


@app.route('/conversation/archive/{s3key}', methods=['POST'], cors=True)
def get_conversation_from_archive(s3key):
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to get conversation from archive for s3 key={}".format(s3key))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])

        s3key = urllib.unquote(s3key)  # The keys have slashes in them so they need to be encoded when they come in
        activity_result = ConversationActivity.load_conversation_dict_from_s3(agent=requesting_agent, s3key=s3key)
        app.log.info("fetched conversation for s3Key {}".format(s3key))
    except Exception as e:
        __handle_exception(e)

    return {
        'conversation': activity_result['conversation']
    }


# ============== Conversation Statuses ==============


@app.route('/conversation/typing/{id}', methods=['PUT'], cors=True)
def set_conversation_author_typing(id):
    request_body = app.current_request.json_body

    if 'author' not in request_body or 'author_id' not in request_body['author'] or 'author_key' not in request_body['author']:
        raise BadRequestError('\'author\' parameter not supplied or invalid!')
    if 'typing' not in request_body:
        raise BadRequestError('\'typing\' parameter not supplied or invalid!')

    app.log.info("Got request to save typing status of conversation id={}, author={}, status={}".format(
        id, request_body['author'], request_body['typing']))
    try:
        ConversationActivity.set_conversation_author_typing_state(id, request_body['author'], request_body['typing'])
        app.log.info("Saved typing status of conversation id={}".format(id))
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/conversation/present/{id}', methods=['PUT'], cors=True)
def set_conversation_author_present(id):
    request_body = app.current_request.json_body

    if 'author' not in request_body or 'author_id' not in request_body['author'] or 'author_key' not in request_body['author']:
        raise BadRequestError('\'author\' parameter not supplied or invalid!')

    app.log.info("Got request to save present status of conversation id={}, author={}".format(
        id, request_body['author']))
    try:
        ConversationActivity.set_conversation_author_present(id, request_body['author'])
        app.log.info("Saved present status of conversation id={}".format(id))
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


# ============== Conversation Queue ==============

@app.route('/conversation/queue/list', methods=['POST'], cors=True)
def get_conversation_queue():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to get conversation queue")
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])

        activity_result = ConversationActivity.get_queued_conversations_by_agent(requesting_agent)
        app.log.info("Listed {} conversations: {}".format(len(activity_result['conversations']),
                                                          activity_result['conversations']))
    except Exception as e:
        __handle_exception(e)

    return {
        'conversations': activity_result['conversations']
    }


@app.route('/conversation/queue/join/{id}', methods=['POST'], cors=True)
def join_conversation_from_queue(id):
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to join conversation queue for id={}".format(id))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])

        activity_result = ConversationActivity.join_queued_conversation(requesting_agent, id)
        app.log.info("Succeeded to join conversation for id: {}, result: {}".format(id, activity_result))
    except Exception as e:
        __handle_exception(e)

    return {
        'customerURL': activity_result['customerURL']
    }


@app.route('/conversation/queue/joinbest', methods=['POST'], cors=True)
def join_best_conversation_from_queue():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to join best conversation queue")
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        languages = ','.join(requesting_agent.get_languages())\
            if type(requesting_agent.get_languages() is list) else requesting_agent.get_languages()
        app.log.info("Request to join best conversation queue was for {}, {}, [{}]".format(
            requesting_agent.get_login(), requesting_agent.get_organization(), languages))

        activity_result = ConversationActivity.join_best_queued_conversation(requesting_agent)
        app.log.info("Succeeded to join conversation, result: {}".format(activity_result))
    except Exception as e:
        __handle_exception(e)

    return {
        'customerURL': activity_result['customerURL']
    }


# ============== Templates ==============

@app.route('/template/full/{id}', methods=['GET'], cors=True)
def get_full_template(id):
    app.log.info("Got request to get full template, template_id={}".format(id))
    try:
        activity_result = CollectionTemplateActivity.get_full_template(id)
        app.log.info("Got full template for template_id={}, result={}".format(id, activity_result))
    except Exception as e:
        __handle_exception(e)

    return {
        'collection_template': activity_result['collection_template']
    }


@app.route('/template/{id}', methods=['POST'], cors=True)
def get_conversation_instructions(id):
    app.log.info("Got request to get conversation instructions, template_id={}".format(id))
    request_body = app.current_request.json_body
    conversation_id = None
    if 'conversation_id' in request_body:
        conversation_id = request_body.get('conversation_id', None)
    try:
        activity_result = CollectionTemplateActivity.get_conversation_instructions(id, conversation_id = conversation_id)
        app.log.info("Got conversation instructions for template_id={}, result=".format(id, activity_result))
    except Exception as e:
        __handle_exception(e)

    return {
        'customer_instructions': activity_result['customer_instructions'],
        'agent_instructions': activity_result['agent_instructions'],
        'customer_instructions_visibile_to_agent': activity_result['customer_instructions_visibile_to_agent'],
        'mturk_title': activity_result['mturk_title'],
        'language': activity_result['language'],
        'definition_references': activity_result['definition_references'],
        'inline_annotation_enabled': activity_result['inline_annotation_enabled'],
        'turn_configurations': activity_result['turn_configurations'],
        'intent_to_slot_mapping': activity_result['intent_to_slot_mapping'],
        'intents': activity_result['intents'],
        'last_updated': activity_result['last_updated'],
        'custom_slots': activity_result.get('custom_slots', None),
        'successful': True
    }


@app.route('/template', methods=['POST'], cors=True)  #, authorizer=iamAuthorizer)
def save_template():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to save template, template_id={}, request={}".format(request_body['template_id'],
                                                                                   request_body))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])

        request_body.pop('token')  # Drop the token off the request body
        activity_result = CollectionTemplateActivity.save_template(template_param=request_body, agent=requesting_agent)
        app.log.info("Successfully saved template for template_id={}, result={}".format(request_body['template_id'],
                                                                                        activity_result))

    except Exception as e:
        __handle_exception(e)

    return {
        'previewURL': activity_result['previewURL'],
        'createConversationURL': activity_result['createConversationURL'],
        'version': activity_result['version'],
        'template_id': activity_result['template_id']
    }


@app.route('/template/{id}', methods=['DELETE'], cors=True)  #, authorizer=iamAuthorizer)
def delete_template(id):
    try:
        app.log.info("Got request to delete template, template_id={}".format(id))
        CollectionTemplateActivity.delete_template(template_id=id)
        app.log.info("Successfully deleted template with template_id={}".format(id))
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/template/editor/lists', methods=['GET'], cors=True)  #, authorizer=iamAuthorizer)
def get_template_editor_lists():
    app.log.info("Got request to get template editor lists")
    try:
        activity_result = CollectionTemplateActivity.get_autofill_editor_lists()
        app.log.info("Fetched template editor lists={}".format(activity_result))
    except Exception as e:
        __handle_exception(e)

    return {
        'language_list': activity_result['language_list'],
        'agent_organization_list': activity_result['agent_organization_list'],
        'customer_organization_list': activity_result['customer_organization_list']
    }


def _list_templates(request_body, template_permission):
    activity_result = CollectionTemplateActivity.get_template_editor_list(
        template_permission,
        start_key=request_body['chunk_key'] if 'chunk_key' in request_body else None,
        client_filters=request_body['filters'] if 'filters' in request_body else None,
        page_size=request_body.get('page_size', None))

    app.log.info("Successfully fetched list of templates")
    app.log.info(" -- {} templates".format(len(activity_result['templates']) if activity_result['templates'] else 0))
    app.log.info(" -- Chunk key: {}".format(activity_result.get('chunk_key')))

    return {
        'templates': activity_result['templates'],
        'chunk_key': activity_result['chunk_key']
    }


@app.route('/template/editor/templates', methods=['POST'], cors=True)  #, authorizer=iamAuthorizer)
def get_templates_for_editor():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to get list of templates to edit")
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        template_permission = TemplatePermission.get_permission(requesting_agent)
        return _list_templates(request_body, template_permission)
    except Exception as e:
        __handle_exception(e)


# This API is different from get_template_editor_lists() as this API enforces IAMAuth and can access all templates.
# We use two separate APIs as both APIs use different authentication mechanism.
@app.route('/scenario', methods=['POST'], authorizer=iam_authorizer)
def list_scenarios():
    request_body = app.current_request.json_body
    if not request_body:
        raise ChaliceViewError("no request body present")

    app.log.info("Got request to get list of templates to edit")
    try:
        return _list_templates(request_body, TemplatePermission.get_admin_permission())
    except Exception as e:
        __handle_exception(e)


def _parse_multipart_request():
    rfile = BytesIO(app.current_request.raw_body)
    content_type = app.current_request.headers['content-type']
    _, parameters = cgi.parse_header(content_type)
    parameters['boundary'] = parameters['boundary'].encode('utf-8')
    parsed = cgi.parse_multipart(rfile, parameters)
    # The cgi library puts values in a single entry list rather than as individual values, remapping them to values
    return {k: parsed[k][0] for k in parsed.keys()}


@app.route('/scenario/validate', methods=['POST'], content_types=['multipart/form-data', 'application/json'], cors=True)
def validate_scenario():
    if app.current_request.headers['content-type'] == 'application/json':
        request_body = app.current_request.json_body
    else:
        request_body = _parse_multipart_request()

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to validate a scenario file")

    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])

        result = validate_scenarios(request_body.get('scenarioFile'),
                                    request_body.get('botFile'),
                                    requesting_agent)
        app.log.info("Successfully validated scenario")

        return {
            'valid': True,
            'scenario': request_body.get('scenarioFile'),
            'bot': request_body.get('botFile'),
            'changes': result
        }
    except UserInputError as e:
        return {
            'valid': False,
            'scenario': request_body.get('scenarioFile'),
            'bot': request_body.get('botFile'),
            'errors': e.errors
        }
    except Exception as e:
        __handle_exception(e)


@app.route('/scenario/update', methods=['POST'], content_types=['multipart/form-data', 'application/json'], cors=True)
def update_scenario():
    if app.current_request.headers['content-type'] == 'application/json':
        request_body = app.current_request.json_body
    else:
        request_body = _parse_multipart_request()

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to update a scenario file")

    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        changes, snapshot_key = update_scenarios(request_body.get('scenarioFile'),
                                                 request_body.get('botFile'),
                                                 requesting_agent)
        app.log.info("Successfully updated scenario")
        return {
            'valid': True,
            'scenario': request_body.get('scenarioFile'),
            'bot': request_body.get('botFile'),
            'changes': changes,
            'snapshot': snapshot_key
        }

    except UserInputError as e:
        return {
            'valid': False,
            'scenario': request_body.get('scenarioFile'),
            'bot': request_body.get('botFile'),
            'errors': e.errors
        }
    except Exception as e:
        __handle_exception(e)


# ============== Collections ==============

@app.route('/collection/create', methods=['POST'], cors=True)
def create_collection():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to create collection, request={}".format(request_body))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])

        request_body.pop('token')  # Drop the token off the request body

        activity_result = CollectionActivity.create_collection(param=request_body, agent=requesting_agent)
        app.log.info("Successfully created collection {}, result={}".format(activity_result['collection_id'],
                                                                            activity_result))

    except Exception as e:
        __handle_exception(e)

    return activity_result


@app.route('/collection/list', methods=['POST'], cors=True)
def list_collections():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to get list of collections")
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = CollectionActivity.list_collections(requesting_agent,
                                                              start_key=request_body['chunk_key'] if 'chunk_key' in request_body else None,
                                                              client_filters=request_body['filters'] if 'filters' in request_body else None)
        app.log.info("Successfully fetched list of collections")
        app.log.info(" -- {} collections".format(len(activity_result['collections']) if activity_result['collections'] else 0))
        app.log.info(" -- Chunk key: {}".format(activity_result.get('chunk_key')))

    except Exception as e:
        __handle_exception(e)

    return {
        'collections': activity_result['collections']
    }


@app.route('/collection', methods=['POST'], cors=True)
def get_collection():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to get a collection")
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = CollectionActivity.fetch(requesting_agent,
                                                   request_body['collection_id'],
                                                   load_detail=request_body.get('load_detail', True))
        app.log.info("Successfully fetched collection: {}".format(activity_result))

    except Exception as e:
        __handle_exception(e)

    return activity_result


@app.route('/collection/update', methods=['POST'], cors=True)
def update_collection():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to update collection, request={}".format(request_body))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])

        request_body.pop('token')  # Drop the token off the request body

        activity_result = CollectionActivity.update_collection(id=request_body['id'],
                                                               templates=request_body['templates'],
                                                               agent=requesting_agent)
        app.log.info("Successfully updated collection {}, result={}".format(activity_result['collection_id'],
                                                                            activity_result))

    except Exception as e:
        __handle_exception(e)

    return activity_result


# ============== Agents ==============

@app.route('/agent', methods=['POST'], cors=True)  #, authorizer=iamAuthorizer)
def create_agent():
    request_body = app.current_request.json_body

    if 'organization' not in request_body:
        raise BadRequestError('\'organization\' parameter not supplied or invalid!')
    if 'login' not in request_body:
        raise BadRequestError('\'login\' parameter not supplied or invalid!')
    if 'name' not in request_body:
        raise BadRequestError('\'name\' parameter not supplied or invalid!')
    if 'password' not in request_body:
        raise BadRequestError('\'password\' parameter not supplied or invalid!')
    if 'languages' not in request_body:
        raise BadRequestError('\'languages\' parameter not supplied or invalid!')
    if 'roles' not in request_body:
        raise BadRequestError('\'roles\' parameter not supplied or invalid!')

    app.log.info("Got request to create agent login {} and name {}".format(request_body['login'], request_body['name']))
    try:
        activity_result = AgentActivity.create_agent(agent_param=request_body)
        app.log.info("Successfully created agent with id {}".format(activity_result['agent_id']))
    except Exception as e:
        __handle_exception(e)

    return {
        'agent_id': activity_result['agent_id']
    }


@app.route('/agent', methods=['PATCH'], cors=True)  #, authorizer=iamAuthorizer)
def update_agent():
    request_body = app.current_request.json_body

    if 'login' not in request_body:
        raise BadRequestError('\'login\' parameter not supplied or invalid!')

    app.log.info("Got request to update agent login {} and name {}".format(request_body['login'], request_body.get('name')))
    try:
        activity_result = AgentActivity.update_agent(agent_param=request_body)
        app.log.info("Successfully updated agent with id {}".format(activity_result['agent_id']))
    except Exception as e:
        __handle_exception(e)

    return {
        'agent_id': activity_result['agent_id']
    }


@app.route('/agent/permissions', methods=['POST'], cors=True)
def get_agent_permissions():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to get agent permissions")
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = AgentActivity.get_agent_interaction_permissions(requesting_agent)
        app.log.info("Successfully fetched agent permissions, result: {}".format(activity_result))
    except Exception as e:
        __handle_exception(e)

    permission_dict = {
        'agent_name': requesting_agent.get_name(),
        'agent_is_valid': True,
        'login': requesting_agent.get_login(),
        'organization': requesting_agent.get_organization()
    }
    permission_dict.update(activity_result)
    return permission_dict


@app.route('/agent/{id}', methods=['GET'], cors=True)  #, authorizer=iamAuthorizer)
def get_agent(id):
    app.log.info("Got request to get agent with id {}".format(id))
    try:
        activity_result = AgentActivity.get_agent_login(id)
        app.log.info("Successfully fetched agent, result: {}".format(activity_result))
    except Exception as e:
        __handle_exception(e)

    return {
        'agent_id': activity_result['agent_id'],
        'organization': activity_result['organization'],
        'name': activity_result['name'],
        'login': activity_result['login'],
        'languages': activity_result['languages'],
        'roles': activity_result['roles'],
        'training_tests': activity_result['training_tests']
    }


@app.route('/agent/bulkstart/{id}', methods=['GET'], cors=True)
def get_agent(id):
    app.log.info("Got request to get the start index for logins beginning with {}".format(id))
    try:
        return AgentActivity.get_start_index(id)
    except Exception as e:
        __handle_exception(e)


@app.route('/agent/{id}', methods=['DELETE'], cors=True)  #, authorizer=iamAuthorizer)
def delete_agent(id):
    # Fetch the agent from the login
    app.log.info("Got request to delete agent with id {}".format(id))
    try:
        activity_result = AgentActivity.get_agent_login(id)
    except Exception as e:
        __handle_exception(e)

    # Delete the agent from the ID
    try:
        AgentActivity.delete_agent(agent_id=activity_result['agent_id'])
        app.log.info("Successfully deleted agent")
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/agent/conversations/open', methods=['POST'], cors=True)
def get_agent_open_conversations():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to list agent conversations")
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = ConversationActivity.fetch_agent_conversations(agent=requesting_agent, open_conversations_only=True)
        app.log.info("Fetched {} conversations".format(len(activity_result['created_conversations'])))
    except Exception as e:
        __handle_exception(e)

    return {
        'conversations': activity_result['created_conversations']
    }


@app.route('/agent/templates', methods=['POST'], cors=True)
def get_agent_available_templates():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = AgentActivity.get_agent_available_templates(requesting_agent)
    except Exception as e:
        __handle_exception(e)

    return {
        'templates': activity_result['templates'],
        'preferred_id': activity_result['preferred_id']
    }


@app.route('/agent/training', methods=['POST'], cors=True)
def submit_training():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        print('Submitting test result for {}'.format(requesting_agent.get_login()))
        AgentActivity.record_test_result(requesting_agent, request_body['test'])
        return {}
    except Exception as e:
        __handle_exception(e)

# ============== Organizations ==============

@app.route('/organization/list', methods=['GET'], cors=True)
def get_organizations_list():

    try:

        activity_result = OrganizationActivity.get_organizations_list()
    except Exception as e:
        __handle_exception(e)

    return {
        'organizations': activity_result['organizations'],
    }


@app.route('/organization/{identifier}', methods=['GET'], cors=True)
def get_organization(identifier):
    try:
        return Organization.fetch_by_id(identifier).serialize()
    except Exception as e:
        __handle_exception(e)


@app.route('/organization/{identifier}/agents', methods=['GET'], cors=True)
def get_organization_agents(identifier):
    try:
        chunk_key = app.current_request.query_params.get('chunk_key') if app.current_request.query_params else None
        return OrganizationActivity.list_agents(identifier, chunk_key)
    except Exception as e:
        __handle_exception(e)


@app.route('/organization', methods=['POST'], cors=True)
def create_organization():
    request_body = app.current_request.json_body

    if 'languages' not in request_body:
        raise BadRequestError('\'languages\' parameter not supplied or invalid!')
    if 'organization_id' not in request_body:
        raise BadRequestError('\'organization_id\' parameter not supplied or invalid!')
    if 'type' not in request_body:
        raise BadRequestError('\'type\' parameter not supplied or invalid!')
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        requesting_org = Organization.fetch_by_id(requesting_agent.get_organization())
        if requesting_agent.is_admin() and requesting_org.is_super_admin_org():
            activity_result = OrganizationActivity.create_organization(organization_param=request_body)
            return {
                'organization_id': activity_result['organization_id']
            }
        else:
            raise BadRequestError('User not authorized')
    except Exception as e:
        __handle_exception(e)


@app.route('/organization', methods=['PATCH'], cors=True)  # , authorizer=iamAuthorizer)
def update_organization():
    request_body = app.current_request.json_body

    if 'organization_id' not in request_body:
        raise BadRequestError('\'organization_id\' parameter not supplied or invalid!')
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        requesting_org = Organization.fetch_by_id(requesting_agent.get_organization())
        if requesting_agent.is_admin() and requesting_org.is_super_admin_org():
            activity_result = OrganizationActivity.update_organization(organization_param=request_body)
            return {
                'organization_id': activity_result['organization_id']
            }
        else:
            raise BadRequestError('User not authorized')
    except Exception as e:
        __handle_exception(e)


# ============== Auth ==============

@app.route('/token/create', methods=['POST'], cors=True)  # , authorizer=iamAuthorizer)
def generate_agent_token():
    request_body = app.current_request.json_body

    if 'agent' not in request_body or 'login' not in request_body['agent'] or 'password' not in request_body['agent']:
        raise BadRequestError('\'agent\' parameter not supplied or invalid!')

    try:
        requesting_agent = AgentActivity.get_agent_from_credentials(request_body['agent']['login'], request_body['agent']['password'])
        activity_result = AgentActivity.generate_token_for_agent(requesting_agent)
    except Exception as e:
        __handle_exception(e)

    return {
        'token': activity_result['token'],
        'ttl': activity_result['ttl']
    }


@app.route('/token/butler', methods=['POST'], cors=True)
def generate_butler_token():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to generate a Butler token")
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        credentials = AgentActivity.generate_butler_token(requesting_agent, 15 * 60)
        app.log.info("Successfully generated token")
        return credentials

    except Exception as e:
        __handle_exception(e)


# ========== Butler Passthru =======

@app.route('/butler/list_state_machines', methods=['POST'], cors=True)
def butler_list_state_machines():
    request_body = app.current_request.json_body
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid')
    app.log.info("Got request to call list_state_machines for Butler")
    try:
        AgentActivity.get_agent_from_token(request_body['token'])
        sfn = AuthUtils.get_butler_session(900).client('stepfunctions')
        request_body.pop('token')
        return ser_dict_dates(sfn.list_state_machines(**request_body))
    except Exception as e:
        __handle_exception(e)


@app.route('/butler/describe_state_machine', methods=['POST'], cors=True)
def butler_describe_state_machine():
    request_body = app.current_request.json_body
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid')
    app.log.info("Got request to call list_state_machines for Butler")
    try:
        AgentActivity.get_agent_from_token(request_body['token'])
        sfn = AuthUtils.get_butler_session(900).client('stepfunctions')
        request_body.pop('token')
        return ser_dict_dates(sfn.describe_state_machine(**request_body))
    except Exception as e:
        __handle_exception(e)


@app.route('/butler/list_executions', methods=['POST'], cors=True)
def butler_list_executions():
    request_body = app.current_request.json_body
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid')
    app.log.info("Got request to call list_state_machines for Butler")
    try:
        AgentActivity.get_agent_from_token(request_body['token'])
        sfn = AuthUtils.get_butler_session(900).client('stepfunctions')
        request_body.pop('token')
        return ser_dict_dates(sfn.list_executions(**request_body))
    except Exception as e:
        __handle_exception(e)


@app.route('/butler/start_execution', methods=['POST'], cors=True)
def butler_start_execution():
    request_body = app.current_request.json_body
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid')
    app.log.info("Got request to call list_state_machines for Butler")
    try:
        AgentActivity.get_agent_from_token(request_body['token'])
        sfn = AuthUtils.get_butler_session(900).client('stepfunctions')
        request_body.pop('token')
        return ser_dict_dates(sfn.start_execution(**request_body))
    except Exception as e:
        __handle_exception(e)


@app.route('/butler/describe_execution', methods=['POST'], cors=True)
def butler_describe_execution():
    request_body = app.current_request.json_body
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid')
    app.log.info("Got request to call describe_execution for Butler")
    try:
        AgentActivity.get_agent_from_token(request_body['token'])
        sfn = AuthUtils.get_butler_session(900).client('stepfunctions')
        request_body.pop('token')
        return ser_dict_dates(sfn.describe_execution(**request_body))
    except Exception as e:
        __handle_exception(e)


@app.route('/butler/get_execution_history', methods=['POST'], cors=True)
def butler_describe_execution():
    request_body = app.current_request.json_body
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid')
    app.log.info("Got request to call get_execution_history for Butler")
    try:
        AgentActivity.get_agent_from_token(request_body['token'])
        sfn = AuthUtils.get_butler_session(900).client('stepfunctions')
        request_body.pop('token')
        return ser_dict_dates(sfn.get_execution_history(**request_body))
    except Exception as e:
        __handle_exception(e)

# ============== Ping ==============

@app.route('/warmup', methods=['GET'])
def ping():
    app.log.info("Received ping request")

    return {
        'success': True
    }


# ============== Admin ==============

@app.route('/admin/approve_hit/{id}', methods=['POST'], cors=True)  #, authorizer=iamAuthorizer)
def approve_hit(id):
    try:
        activity_result = AdminActivity.approve_hit(hit_id=id)
    except Exception as e:
        __handle_exception(e)

    return {
        'successful': True
    }


@app.route('/admin/qualifications/{environment}', methods=['GET'], cors=True)  #, authorizer=iamAuthorizer)
def list_qualifications(environment):

    try:
        activity_result = AdminActivity.list_qualifications(environment=environment)
    except Exception as e:
        __handle_exception(e)

    return {
        'qualifications': activity_result['qualifications']
    }


@app.route('/admin/qualifications/{environment}', methods=['POST'], cors=True)  #, authorizer=iamAuthorizer)
def create_qualification(environment):
    request_body = app.current_request.json_body

    if 'Name' not in request_body:
        raise BadRequestError('\'Name\' parameter not supplied or invalid!')
    if 'Description' not in request_body:
        raise BadRequestError('\'Description\' parameter not supplied or invalid!')
    if 'QualificationTypeStatus' not in request_body:
        raise BadRequestError('\'QualificationTypeStatus\' parameter not supplied or invalid!')

    try:
        activity_result = AdminActivity.create_qualification(environment=environment, qualification_details=request_body)
    except Exception as e:
        __handle_exception(e)

    return {
        'qualification': activity_result['qualification']
    }


@app.route('/admin/qualifications/{environment}', methods=['PATCH'], cors=True)  #, authorizer=iamAuthorizer)
def update_qualification(environment):
    request_body = app.current_request.json_body

    if 'QualificationTypeId' not in request_body:
        raise BadRequestError('\'QualificationTypeId\' parameter not supplied or invalid!')

    try:
        activity_result = AdminActivity.update_qualification(environment=environment, qualification_details=request_body)
    except Exception as e:
        __handle_exception(e)

    return {
        'qualification': activity_result['qualification']
    }


@app.route('/admin/qualifications/{environment}/{qualification_id}', methods=['DELETE'], cors=True)  #, authorizer=iamAuthorizer)
def delete_qualification(environment, qualification_id):
    try:
        AdminActivity.delete_qualification(environment=environment, qualification_id=qualification_id)
    except Exception as e:
        __handle_exception(e)

    return {
        'success': True
    }


@app.route('/admin/mturk/block/{environment}/{mturk_id}', methods=['POST'], cors=True)  #, authorizer=iamAuthorizer)
def block_mturker(environment, mturk_id):
    request_body = app.current_request.json_body
    try:
        AdminActivity.block_mturker(environment=environment, mturk_id=mturk_id, reason=request_body)
    except Exception as e:
        __handle_exception(e)

    return {
        'success': True
    }


@app.route('/admin/mturk/block/{environment}/{mturk_id}', methods=['DELETE'], cors=True)  #, authorizer=iamAuthorizer)
def unblock_mturker(environment, mturk_id):
    request_body = app.current_request.json_body
    try:
        AdminActivity.unblock_mturker(environment=environment, mturk_id=mturk_id, reason=request_body)
    except Exception as e:
        __handle_exception(e)

    return {
        'success': True
    }


@app.route('/admin/mturk/block/{environment}', methods=['GET'], cors=True)  #, authorizer=iamAuthorizer)
def list_blocked_mturkers(environment):

    try:
        activity_result = AdminActivity.list_blocked_mturkers(environment=environment)
    except Exception as e:
        __handle_exception(e)

    return {
        'blocked_list': activity_result['blocked_list']
    }

@app.route('/admin/options', methods=['GET'], cors=True)
def get_admin_options():
    try:
        return AdminActivity.get_admin_options()
    except Exception as e:
        __handle_exception(e)


@app.route('/admin/locale', methods=['POST'], cors=True)
def add_locale():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')

    app.log.info("Got request to get add as locale")
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        return AdminActivity.add_locale(request_body['locale'])
    except Exception as e:
        __handle_exception(e)

# ============== Auto Processing ==============


@app.schedule(Rate(1, unit=Rate.MINUTES), name='process_closed')
def process_closed(event):
    # calculate ending time
    total_time = int(os.environ['process_closed_time'])
    end_time = ((total_time*1000 - (5*1000)) * .9) + time.time()

    closed_conversations = []
    while time.time() < end_time:
        try:
            # process 1 conversation at a time.
            processed_conversations = ConversationActivity.process_closed(1)
            if processed_conversations['reached_end']:
                print('Reached end of Visible elements in Queue')
                break
            print('Processed: ' + str(processed_conversations['processed']))
            # add all of the sublists together here.
            closed_conversations.extend(processed_conversations['processed'])
        except Exception as e:
            __handle_exception(e)
            break

    print('Process closed lambda ending')

    return {
        'processed': closed_conversations
    }


# ============== QA Sample Management ==============

@app.lambda_function(name='qa_sample_updated')
def qa_sample_updated(event, context):
    for record in event['Records']:
        sample_id = record.get('dynamodb', {}).get('Keys', {}).get('id', {}).get('S')
        if not sample_id:
            raise Exception('No sample id provided')
        sample = QASample.fetch(sample_id)
        if not sample:
            raise Exception("Sample not found")
        state = sample.test_state() if record['eventSource'] == 'create_qa_sample' else sample.state
        upload_state = sample.test_upload_state() \
            if record['eventSource'] == 'process_qa_sample' else sample.upload_state

        if state == QASample.STATE_NEW:
            QASampleActivity.build_qa_sample(sample)
        elif upload_state == QASample.UPLOAD_STATE_NEW:
            QASampleActivity.process_qa(sample)
        else:
            logging.info('Will not process unhandled states: {} and {}'.format(state, upload_state))
    return {
        'complete': True
    }


@app.route('/qa/create', methods=['POST'], cors=True)
def create_qa_sample():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to create qa sample for collection {}, request={}".format(request_body['collection_id'],
                                                                                        request_body))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = CollectionActivity.create_qa_sample(collection_id=request_body['collection_id'],
                                                              version_id=request_body['version_id'],
                                                              agent=requesting_agent,
                                                              sample_percentage=request_body.get('sample_percentage', 10),
                                                              min_size=request_body.get('min_size', 50))
        app.log.info("Successfully created qa sample {}, result={}".format(activity_result['id'],
                                                                           activity_result))
        return activity_result
    except Exception as e:
        __handle_exception(e)


@app.route('/qa/get', methods=['POST'], cors=True)
def list_qa_sample():
    request_body = app.current_request.json_body

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to get qa samples for collection {}, request={}".format(request_body['collection_id'],
                                                                                      request_body))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = CollectionActivity.get_qa_samples(collection_id=request_body['collection_id'],
                                                            version_id=request_body['version_id'],
                                                            agent=requesting_agent)
        app.log.info("Successfully retrieved qa samples, result={}".format(activity_result))
        return activity_result
    except Exception as e:
        __handle_exception(e)


@app.route('/qa/sample/download', methods=['POST'], cors=True)
def download_qa_sample():
    request_body = app.current_request.json_body
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to download qa_sample {}".format(request_body['sample_id']))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = QASampleActivity.download(sample_id=request_body['sample_id'],
                                                    agent=requesting_agent)
        app.log.info("Successfully completed creating download url, result={}".format(activity_result))
        return activity_result
    except Exception as e:
        __handle_exception(e)


@app.route('/qa/download', methods=['POST'], cors=True)
def download_qa():
    request_body = app.current_request.json_body
    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to download qa {}".format(request_body['sample_id']))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = QASampleActivity.download_qa(sample_id=request_body['sample_id'],
                                                       agent=requesting_agent)
        app.log.info("Successfully completed creating qa url, result={}".format(activity_result))
        return activity_result
    except Exception as e:
        __handle_exception(e)


@app.route('/qa/upload', methods=['POST'], content_types=['multipart/form-data', 'application/json'], cors=True)
def upload_qa_sample():
    if app.current_request.headers['content-type'] == 'application/json':
        request_body = app.current_request.json_body
    else:
        request_body = _parse_multipart_request()

    if 'token' not in request_body:
        raise BadRequestError('\'token\' parameter not supplied or invalid!')
    app.log.info("Got request to upload qa_sample {}".format(request_body['sample_id']))
    try:
        requesting_agent = AgentActivity.get_agent_from_token(request_body['token'])
        activity_result = QASampleActivity.upload(sample_id=request_body['sample_id'],
                                                  sample_file=request_body['sample_file'],
                                                  agent=requesting_agent)
        app.log.info("Successfully completed upload, result={}".format(activity_result))
        return activity_result
    except Exception as e:
        __handle_exception(e)


# ============== Bot Benchmarking ==============

@app.route('/benchmark/request/queue', methods=['POST'], cors=True)  #, authorizer=iamAuthorizer)
def bot_benchmark_queue_request():
    request_body = app.current_request.json_body

    try:
        request_id = BotBenchmarkActivity.add_request_to_queue(request_body)
    except Exception as e:
        __handle_exception(e)

    return {
        'request_id': request_id
    }


@app.route('/benchmark/request/{id}', methods=['GET'], cors=True)  #, authorizer=iamAuthorizer)
def bot_benchmark_get_request_results(id):
    try:
        results = BotBenchmarkActivity.get_request_results(request_id=id, include_query_sets=False)  # False to the query sets, we just want progress
    except Exception as e:
         __handle_exception(e)

    return {
        'request_id': id,
        'results': results
    }


@app.route('/benchmark/request/{id}', methods=['DELETE'], cors=True)  #, authorizer=iamAuthorizer)
def bot_benchmark_cancel_request(id):
    try:
        results = BotBenchmarkActivity.cancel_request(request_id=id)
    except Exception as e:
        __handle_exception(e)

    return {
        'request_id': id,
        'cancel_state': results
    }


@app.route('/benchmark/input', methods=['GET'], cors=True)
def bot_benchmark_get_input_set():
    try:
        results = BotInputActivity.list_input_sets()
    except Exception as e:
        __handle_exception(e)

    return {
        'input_sets': results['input_sets']
    }


@app.route('/benchmark/input/{id}', methods=['POST'], cors=True)  #, authorizer=iamAuthorizer)
def bot_benchmark_add_input_set(id):
    request_body = app.current_request.json_body

    try:
        input_id = BotInputActivity.add_input_set_to_storage(input_id=id, container=request_body)
    except Exception as e:
        __handle_exception(e)

    return {
        'input_id': input_id
    }


@app.route('/benchmark/bots', methods=['GET'], cors=True)  #, authorizer=iamAuthorizer)
def bot_benchmark_list_bots():
    try:
        results = BotConfigActivity.get_list_of_bots()
    except Exception as e:
        __handle_exception(e)

    return {
        'bots': results
    }

@app.route('/benchmark/bots/{id}', methods=['POST'], cors=True)  #, authorizer=iamAuthorizer)
def bot_benchmark_save_bot(id):
    request_body = app.current_request.json_body

    if 'provider' not in request_body:
        raise BadRequestError('\'provider\' parameter not supplied or invalid!')

    activity_result = BotConfigActivity.save_bot(bot_id=id, bot_params=request_body)

    return {
        'bot_id': activity_result['bot_id']
    }


@app.lambda_function(name='bot_benchmark_queue_handler')
def bot_benchmark_queue_handler(event, context):
    print('Starting Bot Benchmark Lambda')

    if 'Records' in event:  # SQS Event with a record set to start processing
        # Note: record count should only be 1 (SQS trigger configured to deliver 1 record) for MT only execution
        # Employing sub-lambdas for processing and/or timeout handling will allow larger batch processing, however
        # this should not positively affect costs or performance unless request rates are significantly increased.
        record_number = 0
        responses = []
        for record in event['Records']:  # Process each record in the SQS batch
            record_number += 1
            print('Processing record {}/{}'.format(record_number, len(event['Records'])))

            if 'body' not in record:
                raise BadRequestError('\'body\' parameter not found in sqs record or invalid!')
            request = json.loads(record['body'])

            # Validate Input
            if 'bot_config' not in request:
                raise BadRequestError('\'bot_config\' parameter not supplied or invalid!')
            if 'input_id' not in request:
                raise BadRequestError('\'input_id\' parameter not supplied or invalid!')
            # Note: Max Threads is allowed as an optional pass in for per-request overriding, mostly for bot config tuning
            # Note: Request ID is allowed as a pass in to sync between adding to queue and results/execution

            benchmark_response = BotBenchmarkActivity.process_bulk_input_request(bot_config_id=request['bot_config'],
                                                                                 input_id=request['input_id'],
                                                                                 request_id=request['request_id'] if 'request_id' in request else None,
                                                                                 max_thread_time=((context.get_remaining_time_in_millis() - (5 * 1000)) * 0.8)  # Max time is 80% of lambda run time - 5 sec to allow overrun if needed
                                                                                 )
            responses.append(benchmark_response)

        return {
            'event': event,
            'responses': responses
        }
    elif 'request_id' in event:  # Self triggered call to perform processing on an existing request
        benchmark_response = BotBenchmarkActivity.process_existing_request(request_id=event['request_id'],
                                                                           max_thread_time=((context.get_remaining_time_in_millis() - (5 * 1000)) * 0.9)  # Max time is 90% of lambda run time - 5 sec to allow overrun if needed
                                                                           )

        return {
            'event': event,
            'response': benchmark_response
        }
    else:
        raise BadRequestError('Unknown input')


@app.on_sqs_message(name='process_timeout', queue='conversation-timeout', batch_size=1)
def handle_conversation_timeout_sqs(event):
    for record in event:  # Process each record in the SQS batch
        request = json.loads(record.body)

        if 'conversation_id' not in request:
            raise BadRequestError('\'conversation_id\' parameter not supplied or invalid!')

        ConversationActivity.timeout_conversation(conversation_id=request['conversation_id'])

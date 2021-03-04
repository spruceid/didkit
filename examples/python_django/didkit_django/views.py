from django.shortcuts import render
from django.http import HttpResponse
import socket
from django import forms
from django.http import JsonResponse
from didkit_django.issue_credential import issueCredential
from django.views.decorators.csrf import csrf_exempt


def index(request):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()

    context = {
        "url": (request.is_secure() and "https://" or "http://") + IP +
        ":" + request.META["SERVER_PORT"] + "/didkit/wallet",
    }
    return render(request, "didkit_django/index.html", context)


def credential(request):
    context = {
        "credential": issueCredential(request),
    }

    return render(request, "didkit_django/credential.html", context)


@csrf_exempt
def wallet(request):
    credential = issueCredential(request)
    if request.method == 'GET':
        return JsonResponse({
            "type": "CredentialOffer",
            "credentialPreview": credential
        })

    elif request.method == 'POST':
        return JsonResponse(credential)

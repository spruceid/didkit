$(document).ready(async function() {
    let ws = null;
    let uuid = $('#vp-request-form').data("uuid");

    $('#collapse-pres').on('show.bs.collapse', () => {
        ws = new WebSocket('wss://' + window.location.host + '/wss/verifiable-presentation-request');
        ws.addEventListener('open', (event) => {
            ws.send(uuid);
        });
        ws.addEventListener('message', (message) => {
            $('#vp-request-field').val(message.data);
            ws.close();
            $('#vp-request-form').submit();
        });
    });

    $('#collapse-pres').on('hide.bs.collapse', () => {
        if (ws != null) ws.close();
        ws = null;
    });
});

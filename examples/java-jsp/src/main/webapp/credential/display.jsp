<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<html>
<head>
    <title>Java JSP Example - Display Credential</title>
</head>
<body>
<p><a href="${pageContext.request.contextPath}/">Back</a></p>
<p><label>Credential:<textarea id="credential" rows="4" cols="64">${vc}</textarea></label></p>
<button id="chapi-store">Save to CHAPI Wallet</button>

<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
<script src="https://unpkg.com/credential-handler-polyfill@2.1.0/dist/credential-handler-polyfill.min.js"></script>
<script src="https://unpkg.com/uuid@latest/dist/umd/uuidv4.min.js"></script>
<script src="${pageContext.request.contextPath}/chapi.js"></script>
</body>
</html>

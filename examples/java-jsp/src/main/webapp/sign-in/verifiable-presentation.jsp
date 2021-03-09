<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<html>
<head>
    <title>Java JSP Example - Sign In with CHAPI Wallet</title>
</head>
<body>
<p><a href="${pageContext.request.contextPath}/">Back</a></p>
<form id="verifiable-presentation-form" method="post"
      action="${pageContext.request.contextPath}/sign-in/verifiable-presentation">
    <input id="verifiable-presentation-field" name="verifiable-presentation" hidden/>
    <button id="chapi-get">Sign In with CHAPI Wallet</button>
</form>

<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
<script src="https://unpkg.com/credential-handler-polyfill@2.1.0/dist/credential-handler-polyfill.min.js"></script>
<script src="https://unpkg.com/uuid@latest/dist/umd/uuidv4.min.js"></script>
<script src="${pageContext.request.contextPath}/chapi.js"></script>
</body>
</html>

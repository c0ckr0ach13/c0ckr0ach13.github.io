---
# the default layout is 'page'
icon: fas fa-user-secret
order: 4
---

## Tools
<button onclick="loadTool('https://gtfobins.github.io/')">gtfobins</button>
<button onclick="loadTool('https://gchq.github.io/CyberChef/')">CyberChef</button>
<button onclick="loadTool('https://www.revshells.com/')">revshells</button>
<button onclick="loadTool('https://0xby.com/onlinetools/Deserial.html')">Java 反序列化在线解析</button>
<button onclick="loadTool('http://jagt.github.io/python-single-line-convert/index.html')">python-single-line-convert</button>
<button onclick="loadTool('https://tooltt.com/ascii-draw/')">ascii-draw</button>
<button onclick="loadTool('https://chat.openai.com/')">ChatGPT</button>
<button onclick="loadTool('https://web-check.as93.net/')">web-check</button>
<button onclick="loadTool('https://www.cvedetails.com/')">cvedetails</button>
<button onclick="loadTool('https://jwt.io/')">jwt.io</button>
<button onclick="loadTool('https://jsoncrack.com/editor')">JSON CRACK</button>
<button onclick="loadTool('https://privacy.sexy/')">privacy sexy</button>

## Docs
<button onclick="loadTool('https://book.hacktricks.xyz/welcome/readme')">hacktricks</button>
<button onclick="loadTool('https://quickref.cn/index.html')">Quick Reference</button>
<button onclick="loadTool('https://tinyxss.terjanq.me/index.html')">tinyxss</button>
<button onclick="loadTool('https://oi-wiki.org/')">oi-wiki</button>
<button onclick="loadTool('https://portswigger.net/web-security/cross-site-scripting/cheat-sheet')">xss cheat-sheet</button>
<button onclick="loadTool('https://devdocs.io/')">devdocs</button>
<button onclick="loadTool('https://wokough.gitbook.io/iot-firmware-aio/'）">iot-firmware-aio</button>

<iframe id="toolFrame" src="" frameborder="0" width="100%" height="800px"></iframe>

<script>
function loadTool(toolUrl) {
    var toolFrame = document.getElementById('toolFrame');
    toolFrame.src = toolUrl;
    toolFrame.style.backgroundColor = 'darkgrey';
}
</script>
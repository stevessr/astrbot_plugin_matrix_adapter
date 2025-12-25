import bleach
from markdown_it import MarkdownIt

# 可以配置 markdown-it 来启用/禁用特定规则或添加插件
# 这里的 "default" 设置已经很完善，并且默认是安全的
md = MarkdownIt("default")


def markdown_to_html(md_text: str) -> str:
    """
    将 Markdown 文本安全地渲染为 HTML。

    Args:
        md_text: 需要转换的 Markdown 格式的字符串。

    Returns:
        经过转换和清理的 HTML 字符串。
    """
    if not isinstance(md_text, str):
        return ""

    # 1. 使用 markdown-it-py 进行转换
    # render() 方法会将 Markdown 转换为 HTML
    html = md.render(md_text)

    # 2. 使用 bleach 进行严格的 HTML 清理，防止 XSS 攻击
    # 您可以根据需求自定义允许的标签和属性
    allowed_tags = {
        "p",
        "br",
        "strong",
        "b",
        "em",
        "i",
        "code",
        "pre",
        "blockquote",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "ul",
        "ol",
        "li",
        "a",
        "img",
        "del",
    }
    allowed_attrs = {"a": ["href", "title"], "img": ["src", "alt", "title"]}

    cleaned_html = bleach.clean(
        html,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True,  # 移除不允许的标签，而不是转义它们
    )

    return cleaned_html

"""Poll input validation."""


def _validate_poll_input(question, answers, max_selections):
    clean_question = (question or "").strip()
    if not clean_question:
        raise ValueError("question is required for poll")

    clean_answers = [str(a).strip() for a in (answers or []) if str(a).strip()]
    if not clean_answers:
        raise ValueError("answers is required for poll")

    if max_selections < 1:
        max_selections = 1
    if max_selections > len(clean_answers):
        max_selections = len(clean_answers)
    return clean_question, clean_answers, max_selections

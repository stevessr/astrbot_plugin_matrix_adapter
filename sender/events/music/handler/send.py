"""Audio and metadata message sending for Matrix music events."""


async def _send_audio_message(
    client,
    segment,
    room_id,
    reply_to,
    thread_root,
    use_thread,
    is_encrypted_room,
    e2ee_manager,
    thread_is_falling_back,
    use_notice,
    file_path,
    content_type,
    audio_size,
    resolve_type,
    sender,
    title,
    url,
    image,
) -> None:
    filename = file_path.name
    upload_resp = await client.upload_file_path(
        file_path=file_path,
        content_type=content_type,
        filename=filename,
    )
    content_uri = upload_resp["content_uri"]
    body = title or filename
    content_data = {
        "msgtype": "m.audio",
        "body": body,
        "url": content_uri,
        "info": {"mimetype": content_type, "size": audio_size},
    }
    await sender(
        client,
        content_data,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        thread_is_falling_back=thread_is_falling_back,
    )

    if url or image:
        meta_lines = [line for line in [title, url, image] if line]
        meta_body = "\n".join(meta_lines)
        if meta_body:
            meta_content = {
                "msgtype": resolve_type(use_notice),
                "body": meta_body,
            }
            await sender(
                client,
                meta_content,
                room_id,
                reply_to,
                thread_root,
                use_thread,
                is_encrypted_room,
                e2ee_manager,
                thread_is_falling_back=thread_is_falling_back,
            )

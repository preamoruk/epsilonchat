package com.epsilonchat.merkle;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import java.util.ArrayList;
import java.util.List;

public class MessageAdapter extends RecyclerView.Adapter<MessageAdapter.ViewHolder> {

    public static class Message {
        public String sender;
        public String text;
        public String timestamp;
        public boolean isSent;

        public Message(String sender, String text, String timestamp, boolean isSent) {
            this.sender = sender;
            this.text = text;
            this.timestamp = timestamp;
            this.isSent = isSent;
        }
    }

    private List<Message> messages = new ArrayList<>();

    @Override
    public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
            .inflate(R.layout.item_message, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(ViewHolder holder, int position) {
        Message msg = messages.get(position);
        holder.tvSender.setText(msg.isSent ? "You" : msg.sender);
        holder.tvMessage.setText(msg.text);
        holder.tvTime.setText(msg.timestamp);

        if (msg.isSent) {
            holder.tvMessage.setBackgroundResource(R.drawable.msg_sent_bg);
            holder.tvMessage.setTextColor(0xFFFFFFFF);
        } else {
            holder.tvMessage.setBackgroundResource(R.drawable.msg_recv_bg);
            holder.tvMessage.setTextColor(0xFFC9D1D9);
        }
    }

    @Override
    public int getItemCount() {
        return messages.size();
    }

    public void addMessage(Message msg) {
        messages.add(msg);
        notifyItemInserted(messages.size() - 1);
    }

    public void setMessages(List<Message> msgs) {
        messages = msgs;
        notifyDataSetChanged();
    }

    public void clear() {
        messages.clear();
        notifyDataSetChanged();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvSender;
        TextView tvMessage;
        TextView tvTime;

        ViewHolder(View view) {
            super(view);
            tvSender = view.findViewById(R.id.tvSender);
            tvMessage = view.findViewById(R.id.tvMessage);
            tvTime = view.findViewById(R.id.tvTime);
        }
    }
}
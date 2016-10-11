#ifndef	__LIST_H__
#define	__LIST_H__

#include <stddef.h>

typedef struct list_head {
	struct list_head *prev, *next;
} list_head;

#define	LIST_HEAD_INIT(name)	{&(name), &(name)}

#define	LIST_HEAD(name)	\
	struct list_head name = LIST_HEAD_INIT(name)

static inline void list_head_init(struct list_head *head) {
	head->next	= head;
	head->prev	= head;
}

/* prev <-> new <-> next */
static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next) {
	new->prev	= prev;
	new->next	= next;
	next->prev	= new;
	prev->next	= new;
}

/* head <-> new <-> head->next */
static inline void list_add(struct list_head *new, struct list_head *head) {
	__list_add(new, head, head->next);
}

/* head->prev <-> new <-> head */
static inline void list_add_tail(struct list_head *new, struct list_head *head) {
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next) {
	next->prev	= prev;
	prev->next	= next;
}

static inline void list_del(struct list_head *old) {
	__list_del(old->prev, old->next);
}

static inline int list_empty(struct list_head *head) {
	return head->next == head;
}

static inline int list_is_tail(struct list_head *entry, struct list_head *head) {
	return (head == entry->next);
}

#define	list_entry(ptr, type, member)	\
	((type*)((char*)(ptr)-offsetof(type,member)))

#define	list_for_each(iter, head)	\
	for(iter = (head)->next; iter != (head); iter = iter->next)

#define	list_for_each_prev(iter, head)	\
	for(iter = (head)->prev; iter != (head); iter = iter->prev)

#define	list_for_each_safe(iter, iter_next, head)	\
	for(iter = (head)->next, iter_next = iter->next;	\
		iter != head;	\
		iter = iter_next, iter_next = iter->next)

#define	list_for_each_entry(entry, head, type, member)	\
	for(entry = list_entry((head)->next, type, member);	\
		&entry->member != (head);	\
		entry = list_entry(entry->member.next, type, member))

#endif /* __LIST_H__ */

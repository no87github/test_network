/**
 * Copyright (C) 2005, Trend Micro Incorporated. All Rights Reserved. This
 * program is an unpublished copyrighted work which is proprietary to Trend
 * Micro Incorporated and contains confidential information that is not to be
 * reproduced or disclosed to any other person or entity without prior written
 * consent from Trend Micro, Inc. in each and every instance.
 *
 * WARNING: Unauthorized reproduction of this program as well as unauthorized
 * preparation of derivative works based upon the program or distribution of
 * copies by sale, rental, lease or lending are violations of federal copyright
 * laws and state trade secret laws, punishable by civil and criminal
 * penalties.
 */

#ifndef LIST_H
#define LIST_H

#include <unistd.h>

__BEGIN_DECLS

/****************************************************************************/
/* STRUCTURE DECLARATIONS                                                   */
/****************************************************************************/

struct list_head {
    struct list_head *next, *prev;
};

/****************************************************************************/
/* MARCO DECLARATIONS                                                       */
/****************************************************************************/

static inline void list_prefetch(const void *x) {;}

#define LIST_HEAD(name) \
    struct list_head name = { &(name), &(name) }

#define INIT_LIST_HEAD(ptr) do { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/**
 * list_entry - get the struct for this entry
 * @ptr:    the &struct list_head pointer.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
    ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * list_for_each - iterate over a list
 * @pos:    the &struct list_head to use as a loop counter.
 * @head:   the head for your list.
 */
#define list_for_each(pos, head) \
    for (pos = (head)->next, list_prefetch(pos->next); \
         pos != (head); \
         pos = pos->next, list_prefetch(pos->next))
/**
 * list_for_each_prev - iterate over a list backwards
 * @pos:    the &struct list_head to use as a loop counter.
 * @head:   the head for your list.
 */
#define list_for_each_prev(pos, head) \
    for (pos = (head)->prev, list_prefetch(pos->prev); \
         pos != (head); \
         pos = pos->prev, list_prefetch(pos->prev))

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop counter.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; \
         pos != (head); \
         pos = n, n = pos->next)

/**
 * list_for_each_prev_safe - iterate over a list backwards safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop counter.
 * @n:      another &struct list_head to use an temporary storage
 * @head:   the head for your list.
 */
#define list_for_each_prev_safe(pos, n, head) \
    for (pos = (head)->prev, n = pos->prev; \
         pos != (head); \
         pos = n, n = pos->prev)

/**
 * list_for_each_entry - iterate over list of given type
 * @pos:    the type * to use as a loop counter.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member), prefetch(pos->member.next); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member), prefetch(pos->member.next))

/****************************************************************************/
/* FUNCTION DECLARATIONS                                                    */
/****************************************************************************/

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
void list_add(struct list_head *new, struct list_head *head);

/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head. 
 * This is useful for implementing queues.
 */
void list_add_tail(struct list_head *new, struct list_head *head);

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is in an undefined state.
 */
void list_del(struct list_head *entry);

/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
void list_del_init(struct list_head *entry);

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
void list_move(struct list_head *list, struct list_head *head);

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
void list_move_tail(struct list_head *list,  struct list_head *head);

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
int list_empty(struct list_head *head);

/**
 * list_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
void list_splice(struct list_head *list, struct list_head *head);

/**
 * list_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
void list_splice_init(struct list_head *list, struct list_head *head);

__END_DECLS

#endif /* LIST_H */

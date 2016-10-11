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

#include <list.h>

/****************************************************************************/
/* FUNCTION DECLARATIONS                                                    */
/****************************************************************************/

static void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next);
static void __list_del(struct list_head *prev, struct list_head *next);
static void __list_splice(struct list_head *list, struct list_head *head);

/****************************************************************************/
/* FUNCTION DEFINITIONS                                                     */
/****************************************************************************/

/**
 * Insert a new entry between two known consecutive entries. 
 */
static void
__list_add(
    struct list_head *new,
    struct list_head *prev,
    struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

/**
 * Delete a list entry by making the prev/next entries point to each other.
 */
static void
__list_del(
    struct list_head *prev,
    struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * Join two list entry.
 */
static void
__list_splice(
    struct list_head *list,
    struct list_head *head)
{
    struct list_head *first = list->next;
    struct list_head *last = list->prev;
    struct list_head *at = head->next;

    first->prev = head;
    head->next = first;

    last->next = at;
    at->prev = last;
}

/**
 * add a new entry.
 */
void
list_add(
    struct list_head *new,
    struct list_head *head)
{
    __list_add(new, head, head->next);
}

/**
 * add a new entry to the tail.
 */
void
list_add_tail(
    struct list_head *new,
    struct list_head *head)
{
    __list_add(new, head->prev, head);
}

/**
 * deletes entry from list.
 */
void
list_del(
    struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = (void *) 0;
    entry->prev = (void *) 0;
}

/** 
 * deletes entry from list and reinitialize it.
 */
void
list_del_init(
    struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    INIT_LIST_HEAD(entry); 
}

/**
 * delete from one list and add as another's head.
 */
void
list_move(
    struct list_head *list,
    struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add(list, head);
}

/**
 * delete from one list and add as another's tail.
 */
void
list_move_tail(
    struct list_head *list,
    struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add_tail(list, head);
}

/**
 * tests whether a list is empty.
 */
int
list_empty(
    struct list_head *head)
{
    return head->next == head;
}

/**
 * join two lists.
 */
void
list_splice(
    struct list_head *list,
    struct list_head *head)
{
    if (!list_empty(list))
        __list_splice(list, head);
}

/**
 * join two lists and reinitialise the emptied list.
 */
void
list_splice_init(
    struct list_head *list,
    struct list_head *head)
{
    if (!list_empty(list))
    {
        __list_splice(list, head);
        INIT_LIST_HEAD(list);
    }
}

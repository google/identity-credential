/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.identity.storage

import com.android.identity.storage.ephemeral.EphemeralStorage
import kotlinx.coroutines.test.runTest
import kotlinx.io.bytestring.ByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class EphemeralStorageTest {
    companion object {
        val tableSpec = StorageTableSpec("test", false, false)
    }

    @Test
    fun testStorageImplementation() = runTest {
        val storage = EphemeralStorage()
        val table = storage.getTable(tableSpec)
        assertEquals(0, table.enumerate().size)
        assertNull(table.get("foo"))

        val data = ByteString(byteArrayOf(1, 2, 3))
        table.insert("foo", data)
        assertEquals(table.get("foo"), data)
        assertEquals(1, table.enumerate().size.toLong())
        assertEquals("foo", table.enumerate().iterator().next())
        assertNull(table.get("bar"))

        val data2 = ByteString(byteArrayOf(4, 5, 6))
        table.insert("bar", data2)
        assertEquals(table.get("bar"), data2)
        assertEquals(2, table.enumerate().size.toLong())
        table.delete("foo")
        assertNull(table.get("foo"))
        assertNotNull(table.get("bar"))
        assertEquals(1, table.enumerate().size.toLong())
        table.delete("bar")
        assertNull(table.get("bar"))
        assertEquals(0, table.enumerate().size.toLong())
    }

    @Test
    fun testPersistence() = runTest {
        var storage = EphemeralStorage()
        var table = storage.getTable(tableSpec)
        assertEquals(0, table.enumerate().size.toLong())
        assertNull(table.get("foo"))
        val data = ByteString(byteArrayOf(1, 2, 3))
        table.insert("foo", data)

        storage = EphemeralStorage.deserialize(storage.serialize())

        table = storage.getTable(tableSpec)
        assertEquals(1, table.enumerate().size.toLong())
        assertEquals("foo", table.enumerate().iterator().next())
        assertEquals(data, table.get("foo"))
    }
}

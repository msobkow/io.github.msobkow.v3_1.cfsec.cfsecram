
// Description: Java 25 in-memory RAM DbIO implementation for ISOCtryCcy.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamISOCtryCcyTable in-memory RAM DbIO implementation
 *	for ISOCtryCcy.
 */
public class CFSecRamISOCtryCcyTable
	implements ICFSecISOCtryCcyTable
{
	private ICFSecSchema schema;
	private Map< CFSecISOCtryCcyPKey,
				CFSecISOCtryCcyBuff > dictByPKey
		= new HashMap< CFSecISOCtryCcyPKey,
				CFSecISOCtryCcyBuff >();
	private Map< CFSecISOCtryCcyByCtryIdxKey,
				Map< CFSecISOCtryCcyPKey,
					CFSecISOCtryCcyBuff >> dictByCtryIdx
		= new HashMap< CFSecISOCtryCcyByCtryIdxKey,
				Map< CFSecISOCtryCcyPKey,
					CFSecISOCtryCcyBuff >>();
	private Map< CFSecISOCtryCcyByCcyIdxKey,
				Map< CFSecISOCtryCcyPKey,
					CFSecISOCtryCcyBuff >> dictByCcyIdx
		= new HashMap< CFSecISOCtryCcyByCcyIdxKey,
				Map< CFSecISOCtryCcyPKey,
					CFSecISOCtryCcyBuff >>();

	public CFSecRamISOCtryCcyTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createISOCtryCcy( CFSecAuthorization Authorization,
		CFSecISOCtryCcyBuff Buff )
	{
		final String S_ProcName = "createISOCtryCcy";
		CFSecISOCtryCcyPKey pkey = schema.getFactoryISOCtryCcy().newPKey();
		pkey.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );
		pkey.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );
		Buff.setRequiredISOCtryId( pkey.getRequiredISOCtryId() );
		Buff.setRequiredISOCcyId( pkey.getRequiredISOCcyId() );
		CFSecISOCtryCcyByCtryIdxKey keyCtryIdx = schema.getFactoryISOCtryCcy().newCtryIdxKey();
		keyCtryIdx.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );

		CFSecISOCtryCcyByCcyIdxKey keyCcyIdx = schema.getFactoryISOCtryCcy().newCcyIdxKey();
		keyCcyIdx.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
						Buff.getRequiredISOCtryId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"ISOCtryCcyCtry",
						"ISOCtry",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff > subdictCtryIdx;
		if( dictByCtryIdx.containsKey( keyCtryIdx ) ) {
			subdictCtryIdx = dictByCtryIdx.get( keyCtryIdx );
		}
		else {
			subdictCtryIdx = new HashMap< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff >();
			dictByCtryIdx.put( keyCtryIdx, subdictCtryIdx );
		}
		subdictCtryIdx.put( pkey, Buff );

		Map< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff > subdictCcyIdx;
		if( dictByCcyIdx.containsKey( keyCcyIdx ) ) {
			subdictCcyIdx = dictByCcyIdx.get( keyCcyIdx );
		}
		else {
			subdictCcyIdx = new HashMap< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff >();
			dictByCcyIdx.put( keyCcyIdx, subdictCcyIdx );
		}
		subdictCcyIdx.put( pkey, Buff );

	}

	public CFSecISOCtryCcyBuff readDerived( CFSecAuthorization Authorization,
		CFSecISOCtryCcyPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerived";
		CFSecISOCtryCcyPKey key = schema.getFactoryISOCtryCcy().newPKey();
		key.setRequiredISOCtryId( PKey.getRequiredISOCtryId() );
		key.setRequiredISOCcyId( PKey.getRequiredISOCcyId() );
		CFSecISOCtryCcyBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryCcyBuff lockDerived( CFSecAuthorization Authorization,
		CFSecISOCtryCcyPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerived";
		CFSecISOCtryCcyPKey key = schema.getFactoryISOCtryCcy().newPKey();
		key.setRequiredISOCtryId( PKey.getRequiredISOCtryId() );
		key.setRequiredISOCcyId( PKey.getRequiredISOCcyId() );
		CFSecISOCtryCcyBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryCcyBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOCtryCcy.readAllDerived";
		CFSecISOCtryCcyBuff[] retList = new CFSecISOCtryCcyBuff[ dictByPKey.values().size() ];
		Iterator< CFSecISOCtryCcyBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecISOCtryCcyBuff[] readDerivedByCtryIdx( CFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerivedByCtryIdx";
		CFSecISOCtryCcyByCtryIdxKey key = schema.getFactoryISOCtryCcy().newCtryIdxKey();
		key.setRequiredISOCtryId( ISOCtryId );

		CFSecISOCtryCcyBuff[] recArray;
		if( dictByCtryIdx.containsKey( key ) ) {
			Map< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff > subdictCtryIdx
				= dictByCtryIdx.get( key );
			recArray = new CFSecISOCtryCcyBuff[ subdictCtryIdx.size() ];
			Iterator< CFSecISOCtryCcyBuff > iter = subdictCtryIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff > subdictCtryIdx
				= new HashMap< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff >();
			dictByCtryIdx.put( key, subdictCtryIdx );
			recArray = new CFSecISOCtryCcyBuff[0];
		}
		return( recArray );
	}

	public CFSecISOCtryCcyBuff[] readDerivedByCcyIdx( CFSecAuthorization Authorization,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerivedByCcyIdx";
		CFSecISOCtryCcyByCcyIdxKey key = schema.getFactoryISOCtryCcy().newCcyIdxKey();
		key.setRequiredISOCcyId( ISOCcyId );

		CFSecISOCtryCcyBuff[] recArray;
		if( dictByCcyIdx.containsKey( key ) ) {
			Map< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff > subdictCcyIdx
				= dictByCcyIdx.get( key );
			recArray = new CFSecISOCtryCcyBuff[ subdictCcyIdx.size() ];
			Iterator< CFSecISOCtryCcyBuff > iter = subdictCcyIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff > subdictCcyIdx
				= new HashMap< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff >();
			dictByCcyIdx.put( key, subdictCcyIdx );
			recArray = new CFSecISOCtryCcyBuff[0];
		}
		return( recArray );
	}

	public CFSecISOCtryCcyBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		short ISOCtryId,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readDerivedByIdIdx() ";
		CFSecISOCtryCcyPKey key = schema.getFactoryISOCtryCcy().newPKey();
		key.setRequiredISOCtryId( ISOCtryId );
		key.setRequiredISOCcyId( ISOCcyId );

		CFSecISOCtryCcyBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryCcyBuff readBuff( CFSecAuthorization Authorization,
		CFSecISOCtryCcyPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readBuff";
		CFSecISOCtryCcyBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a005" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryCcyBuff lockBuff( CFSecAuthorization Authorization,
		CFSecISOCtryCcyPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecISOCtryCcyBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a005" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryCcyBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readAllBuff";
		CFSecISOCtryCcyBuff buff;
		ArrayList<CFSecISOCtryCcyBuff> filteredList = new ArrayList<CFSecISOCtryCcyBuff>();
		CFSecISOCtryCcyBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a005" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecISOCtryCcyBuff[0] ) );
	}

	public CFSecISOCtryCcyBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		short ISOCtryId,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readBuffByIdIdx() ";
		CFSecISOCtryCcyBuff buff = readDerivedByIdIdx( Authorization,
			ISOCtryId,
			ISOCcyId );
		if( ( buff != null ) && buff.getClassCode().equals( "a005" ) ) {
			return( (CFSecISOCtryCcyBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecISOCtryCcyBuff[] readBuffByCtryIdx( CFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readBuffByCtryIdx() ";
		CFSecISOCtryCcyBuff buff;
		ArrayList<CFSecISOCtryCcyBuff> filteredList = new ArrayList<CFSecISOCtryCcyBuff>();
		CFSecISOCtryCcyBuff[] buffList = readDerivedByCtryIdx( Authorization,
			ISOCtryId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a005" ) ) {
				filteredList.add( (CFSecISOCtryCcyBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecISOCtryCcyBuff[0] ) );
	}

	public CFSecISOCtryCcyBuff[] readBuffByCcyIdx( CFSecAuthorization Authorization,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCtryCcy.readBuffByCcyIdx() ";
		CFSecISOCtryCcyBuff buff;
		ArrayList<CFSecISOCtryCcyBuff> filteredList = new ArrayList<CFSecISOCtryCcyBuff>();
		CFSecISOCtryCcyBuff[] buffList = readDerivedByCcyIdx( Authorization,
			ISOCcyId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a005" ) ) {
				filteredList.add( (CFSecISOCtryCcyBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecISOCtryCcyBuff[0] ) );
	}

	public void updateISOCtryCcy( CFSecAuthorization Authorization,
		CFSecISOCtryCcyBuff Buff )
	{
		CFSecISOCtryCcyPKey pkey = schema.getFactoryISOCtryCcy().newPKey();
		pkey.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );
		pkey.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );
		CFSecISOCtryCcyBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOCtryCcy",
				"Existing record not found",
				"ISOCtryCcy",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOCtryCcy",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecISOCtryCcyByCtryIdxKey existingKeyCtryIdx = schema.getFactoryISOCtryCcy().newCtryIdxKey();
		existingKeyCtryIdx.setRequiredISOCtryId( existing.getRequiredISOCtryId() );

		CFSecISOCtryCcyByCtryIdxKey newKeyCtryIdx = schema.getFactoryISOCtryCcy().newCtryIdxKey();
		newKeyCtryIdx.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );

		CFSecISOCtryCcyByCcyIdxKey existingKeyCcyIdx = schema.getFactoryISOCtryCcy().newCcyIdxKey();
		existingKeyCcyIdx.setRequiredISOCcyId( existing.getRequiredISOCcyId() );

		CFSecISOCtryCcyByCcyIdxKey newKeyCcyIdx = schema.getFactoryISOCtryCcy().newCcyIdxKey();
		newKeyCcyIdx.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
						Buff.getRequiredISOCtryId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateISOCtryCcy",
						"Container",
						"ISOCtryCcyCtry",
						"ISOCtry",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByCtryIdx.get( existingKeyCtryIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByCtryIdx.containsKey( newKeyCtryIdx ) ) {
			subdict = dictByCtryIdx.get( newKeyCtryIdx );
		}
		else {
			subdict = new HashMap< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff >();
			dictByCtryIdx.put( newKeyCtryIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByCcyIdx.get( existingKeyCcyIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByCcyIdx.containsKey( newKeyCcyIdx ) ) {
			subdict = dictByCcyIdx.get( newKeyCcyIdx );
		}
		else {
			subdict = new HashMap< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff >();
			dictByCcyIdx.put( newKeyCcyIdx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteISOCtryCcy( CFSecAuthorization Authorization,
		CFSecISOCtryCcyBuff Buff )
	{
		final String S_ProcName = "CFSecRamISOCtryCcyTable.deleteISOCtryCcy() ";
		String classCode;
		CFSecISOCtryCcyPKey pkey = schema.getFactoryISOCtryCcy().newPKey();
		pkey.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );
		pkey.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );
		CFSecISOCtryCcyBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOCtryCcy",
				pkey );
		}
		CFSecISOCtryCcyByCtryIdxKey keyCtryIdx = schema.getFactoryISOCtryCcy().newCtryIdxKey();
		keyCtryIdx.setRequiredISOCtryId( existing.getRequiredISOCtryId() );

		CFSecISOCtryCcyByCcyIdxKey keyCcyIdx = schema.getFactoryISOCtryCcy().newCcyIdxKey();
		keyCcyIdx.setRequiredISOCcyId( existing.getRequiredISOCcyId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecISOCtryCcyPKey, CFSecISOCtryCcyBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByCtryIdx.get( keyCtryIdx );
		subdict.remove( pkey );

		subdict = dictByCcyIdx.get( keyCcyIdx );
		subdict.remove( pkey );

	}
	public void deleteISOCtryCcyByIdIdx( CFSecAuthorization Authorization,
		short argISOCtryId,
		short argISOCcyId )
	{
		CFSecISOCtryCcyPKey key = schema.getFactoryISOCtryCcy().newPKey();
		key.setRequiredISOCtryId( argISOCtryId );
		key.setRequiredISOCcyId( argISOCcyId );
		deleteISOCtryCcyByIdIdx( Authorization, key );
	}

	public void deleteISOCtryCcyByIdIdx( CFSecAuthorization Authorization,
		CFSecISOCtryCcyPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecISOCtryCcyBuff cur;
		LinkedList<CFSecISOCtryCcyBuff> matchSet = new LinkedList<CFSecISOCtryCcyBuff>();
		Iterator<CFSecISOCtryCcyBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOCtryCcyBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOCtryCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId(),
				cur.getRequiredISOCcyId() );
			deleteISOCtryCcy( Authorization, cur );
		}
	}

	public void deleteISOCtryCcyByCtryIdx( CFSecAuthorization Authorization,
		short argISOCtryId )
	{
		CFSecISOCtryCcyByCtryIdxKey key = schema.getFactoryISOCtryCcy().newCtryIdxKey();
		key.setRequiredISOCtryId( argISOCtryId );
		deleteISOCtryCcyByCtryIdx( Authorization, key );
	}

	public void deleteISOCtryCcyByCtryIdx( CFSecAuthorization Authorization,
		CFSecISOCtryCcyByCtryIdxKey argKey )
	{
		CFSecISOCtryCcyBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecISOCtryCcyBuff> matchSet = new LinkedList<CFSecISOCtryCcyBuff>();
		Iterator<CFSecISOCtryCcyBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOCtryCcyBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOCtryCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId(),
				cur.getRequiredISOCcyId() );
			deleteISOCtryCcy( Authorization, cur );
		}
	}

	public void deleteISOCtryCcyByCcyIdx( CFSecAuthorization Authorization,
		short argISOCcyId )
	{
		CFSecISOCtryCcyByCcyIdxKey key = schema.getFactoryISOCtryCcy().newCcyIdxKey();
		key.setRequiredISOCcyId( argISOCcyId );
		deleteISOCtryCcyByCcyIdx( Authorization, key );
	}

	public void deleteISOCtryCcyByCcyIdx( CFSecAuthorization Authorization,
		CFSecISOCtryCcyByCcyIdxKey argKey )
	{
		CFSecISOCtryCcyBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecISOCtryCcyBuff> matchSet = new LinkedList<CFSecISOCtryCcyBuff>();
		Iterator<CFSecISOCtryCcyBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOCtryCcyBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOCtryCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId(),
				cur.getRequiredISOCcyId() );
			deleteISOCtryCcy( Authorization, cur );
		}
	}
}
